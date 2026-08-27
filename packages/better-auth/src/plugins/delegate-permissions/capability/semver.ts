/**
 * Closed v1 semver algebra for DP scope matching / attenuation.
 *
 * Supported range forms:
 * - exact: `1.2.3`
 * - wildcard: `1.2.x`, `1.2.*`, `1.x`, `1.*`
 * - caret: `^1.2.3`
 * - tilde: `~1.2.3`
 * - comparator pair: `>=1.2.3 <2.0.0`
 *
 * Prerelease versions fail closed unless the range is an exact match to that
 * prerelease string.
 */

export type SemVer = {
	readonly major: number;
	readonly minor: number;
	readonly patch: number;
	readonly prerelease: string | null;
};

/** Interval over release versions. Exact points use lo===hi with both inclusive. */
export type SemVerInterval = {
	readonly lo: SemVer;
	readonly hi: SemVer | null;
	readonly loInclusive: boolean;
	readonly hiInclusive: boolean;
};

const EXACT_RE =
	/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/;
const WILDCARD_RE =
	/^(0|[1-9]\d*)(?:\.(0|[1-9]\d*|x|\*))?(?:\.(0|[1-9]\d*|x|\*))?$/i;
const CARET_RE =
	/^\^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const TILDE_RE =
	/^~(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const GTE_LT_RE =
	/^>=\s*(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\s+<\s*(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function ver(
	major: number,
	minor: number,
	patch: number,
	prerelease: string | null = null,
): SemVer {
	return { major, minor, patch, prerelease };
}

export function parseExactVersion(input: string): SemVer | null {
	const m = EXACT_RE.exec(input.trim());
	if (!m) {
		return null;
	}
	return ver(Number(m[1]), Number(m[2]), Number(m[3]), m[4] ?? null);
}

export function isExactVersion(input: string): boolean {
	return parseExactVersion(input) !== null;
}

function cmpCore(a: SemVer, b: SemVer): number {
	if (a.major !== b.major) {
		return a.major < b.major ? -1 : 1;
	}
	if (a.minor !== b.minor) {
		return a.minor < b.minor ? -1 : 1;
	}
	if (a.patch !== b.patch) {
		return a.patch < b.patch ? -1 : 1;
	}
	return 0;
}

function cmpSemVer(a: SemVer, b: SemVer): number {
	const core = cmpCore(a, b);
	if (core !== 0) {
		return core;
	}
	if (a.prerelease === null && b.prerelease === null) {
		return 0;
	}
	if (a.prerelease === null) {
		return 1;
	}
	if (b.prerelease === null) {
		return -1;
	}
	if (a.prerelease === b.prerelease) {
		return 0;
	}
	return a.prerelease < b.prerelease ? -1 : 1;
}

function bumpMajor(v: SemVer): SemVer {
	return ver(v.major + 1, 0, 0);
}

function bumpMinor(v: SemVer): SemVer {
	return ver(v.major, v.minor + 1, 0);
}

function isClosedPoint(iv: SemVerInterval): boolean {
	return (
		iv.hi !== null &&
		iv.loInclusive &&
		iv.hiInclusive &&
		cmpSemVer(iv.lo, iv.hi) === 0
	);
}

/**
 * Parse a v1 range into a single interval. Returns null if unsupported.
 */
export function parseRangeToInterval(range: string): SemVerInterval | null {
	const raw = range.trim();
	if (raw.length === 0) {
		return null;
	}

	const exact = parseExactVersion(raw);
	if (exact) {
		return {
			lo: exact,
			hi: exact,
			loInclusive: true,
			hiInclusive: true,
		};
	}

	const caret = CARET_RE.exec(raw);
	if (caret) {
		const lo = ver(Number(caret[1]), Number(caret[2]), Number(caret[3]));
		const hi =
			lo.major === 0
				? lo.minor === 0
					? ver(0, 0, lo.patch + 1)
					: bumpMinor(lo)
				: bumpMajor(lo);
		return { lo, hi, loInclusive: true, hiInclusive: false };
	}

	const tilde = TILDE_RE.exec(raw);
	if (tilde) {
		const lo = ver(Number(tilde[1]), Number(tilde[2]), Number(tilde[3]));
		return {
			lo,
			hi: bumpMinor(lo),
			loInclusive: true,
			hiInclusive: false,
		};
	}

	const gteLt = GTE_LT_RE.exec(raw);
	if (gteLt) {
		return {
			lo: ver(Number(gteLt[1]), Number(gteLt[2]), Number(gteLt[3])),
			hi: ver(Number(gteLt[4]), Number(gteLt[5]), Number(gteLt[6])),
			loInclusive: true,
			hiInclusive: false,
		};
	}

	const wild = WILDCARD_RE.exec(raw);
	if (wild) {
		const major = Number(wild[1]);
		const minorTok = wild[2];
		const patchTok = wild[3];
		if (minorTok === undefined || minorTok === "x" || minorTok === "*") {
			return {
				lo: ver(major, 0, 0),
				hi: ver(major + 1, 0, 0),
				loInclusive: true,
				hiInclusive: false,
			};
		}
		const minor = Number(minorTok);
		if (patchTok === undefined || patchTok === "x" || patchTok === "*") {
			return {
				lo: ver(major, minor, 0),
				hi: ver(major, minor + 1, 0),
				loInclusive: true,
				hiInclusive: false,
			};
		}
		return null;
	}

	return null;
}

function inInterval(v: SemVer, iv: SemVerInterval): boolean {
	if (v.prerelease !== null) {
		return isClosedPoint(iv) && cmpSemVer(v, iv.lo) === 0;
	}

	const loCmp = cmpSemVer(v, iv.lo);
	if (iv.loInclusive ? loCmp < 0 : loCmp <= 0) {
		return false;
	}
	if (iv.hi === null) {
		return true;
	}
	const hiCmp = cmpSemVer(v, iv.hi);
	if (iv.hiInclusive ? hiCmp > 0 : hiCmp >= 0) {
		return false;
	}
	return true;
}

/** True if exact `version` satisfies `range`. */
export function semverSatisfies(version: string, range: string): boolean {
	const v = parseExactVersion(version);
	const iv = parseRangeToInterval(range);
	if (!v || !iv) {
		return false;
	}
	return inInterval(v, iv);
}

function intervalSubset(
	child: SemVerInterval,
	parent: SemVerInterval,
): boolean {
	// child.lo must be >= parent.lo (respecting inclusivity)
	const loCmp = cmpSemVer(child.lo, parent.lo);
	if (loCmp < 0) {
		return false;
	}
	if (loCmp === 0 && child.loInclusive && !parent.loInclusive) {
		return false;
	}

	if (parent.hi === null) {
		return true;
	}
	if (child.hi === null) {
		return false;
	}
	const hiCmp = cmpSemVer(child.hi, parent.hi);
	if (hiCmp > 0) {
		return false;
	}
	if (hiCmp === 0 && child.hiInclusive && !parent.hiInclusive) {
		return false;
	}
	return true;
}

/**
 * True if every version matched by `childRange` is also matched by `parentRange`.
 */
export function semverRangeSubset(
	childRange: string,
	parentRange: string,
): boolean {
	const child = parseRangeToInterval(childRange);
	const parent = parseRangeToInterval(parentRange);
	if (!child || !parent) {
		return false;
	}
	return intervalSubset(child, parent);
}

/** True if two ranges / versions have overlapping version sets. */
export function semverRangesOverlap(a: string, b: string): boolean {
	const ia = parseRangeToInterval(a);
	const ib = parseRangeToInterval(b);
	if (!ia || !ib) {
		return false;
	}
	if (isClosedPoint(ia)) {
		return inInterval(ia.lo, ib);
	}
	if (isClosedPoint(ib)) {
		return inInterval(ib.lo, ia);
	}

	// a.lo < b.hi (with inclusivity) AND b.lo < a.hi
	const aLoBeforeBHi =
		ib.hi === null ||
		cmpSemVer(ia.lo, ib.hi) < 0 ||
		(cmpSemVer(ia.lo, ib.hi) === 0 && ia.loInclusive && ib.hiInclusive);
	const bLoBeforeAHi =
		ia.hi === null ||
		cmpSemVer(ib.lo, ia.hi) < 0 ||
		(cmpSemVer(ib.lo, ia.hi) === 0 && ib.loInclusive && ia.hiInclusive);
	return aLoBeforeBHi && bLoBeforeAHi;
}
