import {
	isExactVersion,
	semverRangeSubset,
	semverRangesOverlap,
	semverSatisfies,
} from "./semver";
import type { ScopeAlgebra, ScopeMap } from "./types";

/**
 * Whether `child` is a DNS-style prefix subset of `parent` for left-hand zone labels.
 * Parent `""` covers all. Child matches parent exactly or ends with `.${parent}`.
 */
export function dnsPrefixSubset(child: string, parent: string): boolean {
	if (parent === "") {
		return true;
	}
	if (child === parent) {
		return true;
	}
	return child.endsWith(`.${parent}`);
}

/**
 * Whether `child` is a path-prefix subset of `parent` for rightward path trees.
 * Parent `""` covers all. Match is segment-bounded (`parent + "/"`), not raw startsWith.
 */
export function pathPrefixSubset(child: string, parent: string): boolean {
	if (parent === "") {
		return true;
	}
	if (child === parent) {
		return true;
	}
	return child.startsWith(`${parent}/`);
}

function asStringList(value: string | readonly string[]): readonly string[] {
	return typeof value === "string" ? [value] : value;
}

/**
 * Whether child scope value is ⊆ parent scope value under the given algebra.
 *
 * For `semver`: exact version ⊆ range uses satisfies; range ⊆ range uses range subset.
 */
export function scopeValueSubset(
	child: string | readonly string[],
	parent: string | readonly string[],
	algebra: ScopeAlgebra,
): boolean {
	switch (algebra) {
		case "exact": {
			const c = asStringList(child);
			const p = asStringList(parent);
			if (c.length !== 1 || p.length !== 1) {
				return false;
			}
			return c[0] === p[0];
		}
		case "dns_prefix": {
			const c = asStringList(child);
			const p = asStringList(parent);
			if (c.length !== 1 || p.length !== 1) {
				return false;
			}
			return dnsPrefixSubset(c[0]!, p[0]!);
		}
		case "path_prefix": {
			const c = asStringList(child);
			const p = asStringList(parent);
			if (c.length !== 1 || p.length !== 1) {
				return false;
			}
			return pathPrefixSubset(c[0]!, p[0]!);
		}
		case "set": {
			const c = asStringList(child);
			const p = new Set(asStringList(parent));
			return c.every((member) => p.has(member));
		}
		case "semver": {
			const children = asStringList(child);
			const parents = asStringList(parent);
			if (children.length === 0 || parents.length === 0) {
				return false;
			}
			// Exact version against range(s) — authorize path.
			if (children.length === 1 && isExactVersion(children[0]!)) {
				return parents.some((range) => semverSatisfies(children[0]!, range));
			}
			// Range ⊆ range — attenuation path.
			return children.every((cr) =>
				parents.some((pr) => semverRangeSubset(cr, pr)),
			);
		}
		default: {
			const _exhaustive: never = algebra;
			return _exhaustive;
		}
	}
}

/**
 * Whether two scope values overlap (share any matching resource) under algebra.
 * Used for deny-override detection during assertSubset.
 */
export function scopeValuesOverlap(
	a: string | readonly string[],
	b: string | readonly string[],
	algebra: ScopeAlgebra,
): boolean {
	switch (algebra) {
		case "exact": {
			const aa = asStringList(a);
			const bb = asStringList(b);
			return aa.length === 1 && bb.length === 1 && aa[0] === bb[0];
		}
		case "dns_prefix": {
			const aa = asStringList(a);
			const bb = asStringList(b);
			if (aa.length !== 1 || bb.length !== 1) {
				return false;
			}
			return dnsPrefixSubset(aa[0]!, bb[0]!) || dnsPrefixSubset(bb[0]!, aa[0]!);
		}
		case "path_prefix": {
			const aa = asStringList(a);
			const bb = asStringList(b);
			if (aa.length !== 1 || bb.length !== 1) {
				return false;
			}
			return (
				pathPrefixSubset(aa[0]!, bb[0]!) || pathPrefixSubset(bb[0]!, aa[0]!)
			);
		}
		case "set": {
			const setB = new Set(asStringList(b));
			return asStringList(a).some((m) => setB.has(m));
		}
		case "semver": {
			const aa = asStringList(a);
			const bb = asStringList(b);
			return aa.some((x) => bb.some((y) => semverRangesOverlap(x, y)));
		}
		default: {
			const _exhaustive: never = algebra;
			return _exhaustive;
		}
	}
}

/**
 * Whether child ScopeMap is ⊆ parent ScopeMap.
 */
export function scopeMapSubset(
	child: ScopeMap,
	parent: ScopeMap,
	algebraFor: (dimension: string) => ScopeAlgebra | undefined,
): { ok: true } | { ok: false; dimension: string; message: string } {
	const dimensions = new Set([...Object.keys(child), ...Object.keys(parent)]);

	for (const dimension of dimensions) {
		const parentValue = parent[dimension];
		const childValue = child[dimension];

		if (parentValue === undefined) {
			continue;
		}

		if (childValue === undefined) {
			return {
				ok: false,
				dimension,
				message: `child omits restricted scope dimension "${dimension}"`,
			};
		}

		const algebra = algebraFor(dimension);
		if (!algebra) {
			return {
				ok: false,
				dimension,
				message: `unknown scope dimension "${dimension}"`,
			};
		}

		if (!scopeValueSubset(childValue, parentValue, algebra)) {
			return {
				ok: false,
				dimension,
				message: `scope dimension "${dimension}" is not a subset under ${algebra}`,
			};
		}
	}

	return { ok: true };
}

/**
 * Whether allowScope overlaps denyScope (child allow would authorize something
 * the deny covers). Omitted dimensions on the allow mean ALL → overlap on that dim.
 */
export function scopesOverlapDeny(
	allowScope: ScopeMap,
	denyScope: ScopeMap,
	algebraFor: (dimension: string) => ScopeAlgebra | undefined,
): boolean {
	for (const [dimension, denyValue] of Object.entries(denyScope)) {
		const allowValue = allowScope[dimension];
		if (allowValue === undefined) {
			continue;
		}
		const algebra = algebraFor(dimension);
		if (!algebra) {
			return false;
		}
		if (!scopeValuesOverlap(allowValue, denyValue, algebra)) {
			return false;
		}
	}
	return true;
}

/**
 * Whether a resource satisfies a grant scope for authorization.
 */
export function resourceSatisfiesScope(
	resource: ScopeMap,
	grantScope: ScopeMap,
	algebraFor: (dimension: string) => ScopeAlgebra | undefined,
): boolean {
	for (const [dimension, grantValue] of Object.entries(grantScope)) {
		const resourceValue = resource[dimension];
		if (resourceValue === undefined) {
			return false;
		}
		const algebra = algebraFor(dimension);
		if (!algebra) {
			return false;
		}
		if (!scopeValueSubset(resourceValue, grantValue, algebra)) {
			return false;
		}
	}
	return true;
}
