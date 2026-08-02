import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const DELEGATE_PERMISSIONS_ERROR_CODES = defineErrorCodes({
	CATALOG_NOT_SEEDED: "Delegate-permissions catalog has not been seeded",
	UNKNOWN_ACTION: "Action is not defined in the catalog",
	UNKNOWN_SCOPE_DIMENSION: "Scope dimension is not defined in the catalog",
	SUBSET_VIOLATION: "Child capability set is not a subset of the parent",
	NOT_AUTHORIZED: "Principal is not authorized for this action",
	NO_PRINCIPAL_GRANT: "User has no principal capability grant",
	NO_SESSION_GRANT: "Session has no issued capability grant",
	GRANT_EXPIRED: "Capability grant has expired",
	INVALID_CAPABILITY_SET: "Capability set payload is invalid",
	SEED_DISABLED: "Catalog seeding is disabled for this deployment",
	ENTITY_EXISTS: "Entity already exists",
	ENTITY_NOT_FOUND: "Entity not found",
	CREDENTIAL_NOT_FOUND: "Credential not found",
	NAME_OCCUPIED: "Name is already occupied by another role",
	NAME_CONFLICT: "Name cannot be both zone authority and machine",
	PACKAGE_FORBIDDEN: "Action is forbidden for this entity package",
	COSIGN_REQUIRED: "IDR co-sign is required for this credential",
	SEAT_BIND_FAILED: "Failed to bind a permanent machine seat",
	ISSUER_UNAUTHORIZED: "Issuer is not allowed to create this credential",
	INVALID_HOST: "Machine host name is invalid for the entity",
});
