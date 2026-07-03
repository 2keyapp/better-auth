#!/usr/bin/env node
/**
 * Build and pack Better Auth workspace packages, then force-push standalone
 * artifacts to git branches for git-dependency consumers.
 *
 * Consumer example (package.json):
 *   "better-auth": "github:2keyapp/better-auth#release"
 *   "@better-auth/scim": "github:2keyapp/better-auth#release-scim"
 */
import { execFileSync } from "node:child_process";
import {
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "../..");
const configPath = join(__dirname, "../release-branch.config.json");
const config = JSON.parse(readFileSync(configPath, "utf8"));
const dryRun = process.argv.includes("--dry-run");

function run(cmd, args, options = {}) {
	if (dryRun && cmd === "git" && args[0] === "push") {
		console.log(`[dry-run] ${cmd} ${args.join(" ")}`);
		return "";
	}
	return execFileSync(cmd, args, {
		stdio: options.capture ? "pipe" : "inherit",
		cwd: options.cwd ?? root,
		encoding: options.capture ? "utf8" : undefined,
	});
}

function gitCapture(args, cwd) {
	return run("git", args, { cwd, capture: true }).trim();
}

function preparePackageJson(extractDir) {
	const pkgJsonPath = join(extractDir, "package.json");
	const { devDependencies: _devDependencies, ...published } = JSON.parse(
		readFileSync(pkgJsonPath, "utf8"),
	);

	if (config.repository?.url) {
		published.repository = {
			...published.repository,
			url: config.repository.url,
		};
	}

	writeFileSync(pkgJsonPath, `${JSON.stringify(published, null, "\t")}\n`);
	return published;
}

function publishPackage(pkg) {
	const workDir = join(tmpdir(), `ba-release-${process.pid}-${Date.now()}`);
	const packDir = join(workDir, "pack");
	const extractDir = join(workDir, "release");

	mkdirSync(packDir, { recursive: true });
	mkdirSync(extractDir, { recursive: true });

	console.log(`\n==> ${pkg.filter} -> branch ${pkg.branch}`);

	run("pnpm", ["--filter", `${pkg.filter}...`, "build"]);
	run("pnpm", ["--filter", pkg.filter, "pack", "--pack-destination", packDir]);

	const tarball = readdirSync(packDir).find((file) => file.endsWith(".tgz"));
	if (!tarball) {
		throw new Error(`No tarball produced for ${pkg.filter}`);
	}

	run("tar", [
		"-xzf",
		join(packDir, tarball),
		"-C",
		extractDir,
		"--strip-components=1",
	]);

	const sourceCommit =
		process.env.GITHUB_SHA ?? gitCapture(["rev-parse", "HEAD"]);
	const sourceBranch =
		process.env.GITHUB_REF_NAME ??
		gitCapture(["rev-parse", "--abbrev-ref", "HEAD"]);

	writeFileSync(
		join(extractDir, "RELEASE.json"),
		`${JSON.stringify(
			{
				name: pkg.filter,
				branch: pkg.branch,
				sourceCommit,
				sourceBranch,
				builtAt: new Date().toISOString(),
			},
			null,
			"\t",
		)}\n`,
	);

	const pkgJson = preparePackageJson(extractDir);
	const shortSha = sourceCommit.slice(0, 7);
	const commitMessage = `release: ${pkgJson.name}@${pkgJson.version} (${shortSha})`;

	if (dryRun) {
		console.log(
			`[dry-run] would push ${pkgJson.name}@${pkgJson.version} to ${pkg.branch}`,
		);
		rmSync(workDir, { recursive: true, force: true });
		return;
	}

	if (!process.env.GITHUB_TOKEN) {
		throw new Error("GITHUB_TOKEN is required to push release branches");
	}

	const repository =
		process.env.GITHUB_REPOSITORY ??
		gitCapture(["remote", "get-url", "origin"])
			.replace(/^git@github.com:/, "")
			.replace(/^https:\/\/github.com\//, "")
			.replace(/\.git$/, "");

	const remote =
		process.env.RELEASE_REMOTE ??
		`https://x-access-token:${process.env.GITHUB_TOKEN}@github.com/${repository}.git`;

	run("git", ["init"], { cwd: extractDir });
	run("git", ["checkout", "-B", pkg.branch], { cwd: extractDir });
	run("git", ["config", "user.name", config.git.userName], { cwd: extractDir });
	run("git", ["config", "user.email", config.git.userEmail], {
		cwd: extractDir,
	});
	run("git", ["add", "-A"], { cwd: extractDir });
	run("git", ["commit", "-m", commitMessage], { cwd: extractDir });
	run("git", ["remote", "add", "origin", remote], { cwd: extractDir });
	run("git", ["push", "-f", "origin", `${pkg.branch}:${pkg.branch}`], {
		cwd: extractDir,
	});

	if (pkg.tagPrefix) {
		const tag = `${pkg.tagPrefix}${pkgJson.version}`;
		run("git", ["tag", "-f", tag], { cwd: extractDir });
		run("git", ["push", "-f", "origin", tag], { cwd: extractDir });
	}

	rmSync(workDir, { recursive: true, force: true });
}

for (const pkg of config.packages) {
	publishPackage(pkg);
}

console.log("\nRelease branches updated.");
