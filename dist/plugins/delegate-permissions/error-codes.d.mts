import * as _better_auth_core_utils_error_codes0 from "@better-auth/core/utils/error-codes";

//#region src/plugins/delegate-permissions/error-codes.d.ts
declare const DELEGATE_PERMISSIONS_ERROR_CODES: {
  UNKNOWN_ACTION: _better_auth_core_utils_error_codes0.RawError<"UNKNOWN_ACTION">;
  UNKNOWN_SCOPE_DIMENSION: _better_auth_core_utils_error_codes0.RawError<"UNKNOWN_SCOPE_DIMENSION">;
  NOT_AUTHORIZED: _better_auth_core_utils_error_codes0.RawError<"NOT_AUTHORIZED">;
  SUBSET_VIOLATION: _better_auth_core_utils_error_codes0.RawError<"SUBSET_VIOLATION">;
  CATALOG_NOT_SEEDED: _better_auth_core_utils_error_codes0.RawError<"CATALOG_NOT_SEEDED">;
  NO_PRINCIPAL_GRANT: _better_auth_core_utils_error_codes0.RawError<"NO_PRINCIPAL_GRANT">;
  NO_SESSION_GRANT: _better_auth_core_utils_error_codes0.RawError<"NO_SESSION_GRANT">;
  GRANT_EXPIRED: _better_auth_core_utils_error_codes0.RawError<"GRANT_EXPIRED">;
  INVALID_CAPABILITY_SET: _better_auth_core_utils_error_codes0.RawError<"INVALID_CAPABILITY_SET">;
  SEED_DISABLED: _better_auth_core_utils_error_codes0.RawError<"SEED_DISABLED">;
  ENTITY_EXISTS: _better_auth_core_utils_error_codes0.RawError<"ENTITY_EXISTS">;
  ENTITY_NOT_FOUND: _better_auth_core_utils_error_codes0.RawError<"ENTITY_NOT_FOUND">;
  CREDENTIAL_NOT_FOUND: _better_auth_core_utils_error_codes0.RawError<"CREDENTIAL_NOT_FOUND">;
  NAME_OCCUPIED: _better_auth_core_utils_error_codes0.RawError<"NAME_OCCUPIED">;
  NAME_CONFLICT: _better_auth_core_utils_error_codes0.RawError<"NAME_CONFLICT">;
  PACKAGE_FORBIDDEN: _better_auth_core_utils_error_codes0.RawError<"PACKAGE_FORBIDDEN">;
  COSIGN_REQUIRED: _better_auth_core_utils_error_codes0.RawError<"COSIGN_REQUIRED">;
  SEAT_BIND_FAILED: _better_auth_core_utils_error_codes0.RawError<"SEAT_BIND_FAILED">;
  ISSUER_UNAUTHORIZED: _better_auth_core_utils_error_codes0.RawError<"ISSUER_UNAUTHORIZED">;
  INVALID_HOST: _better_auth_core_utils_error_codes0.RawError<"INVALID_HOST">;
  ENROLL_NOT_FOUND: _better_auth_core_utils_error_codes0.RawError<"ENROLL_NOT_FOUND">;
  ENROLL_NOT_PENDING: _better_auth_core_utils_error_codes0.RawError<"ENROLL_NOT_PENDING">;
  ENROLL_NOT_READY: _better_auth_core_utils_error_codes0.RawError<"ENROLL_NOT_READY">;
  INVALID_CSR: _better_auth_core_utils_error_codes0.RawError<"INVALID_CSR">;
  CERT_MISMATCH: _better_auth_core_utils_error_codes0.RawError<"CERT_MISMATCH">;
  CA_CERT_REQUIRED: _better_auth_core_utils_error_codes0.RawError<"CA_CERT_REQUIRED">;
  CREDENTIAL_ALREADY_REVOKED: _better_auth_core_utils_error_codes0.RawError<"CREDENTIAL_ALREADY_REVOKED">;
  CREDENTIAL_NOT_ACTIVE: _better_auth_core_utils_error_codes0.RawError<"CREDENTIAL_NOT_ACTIVE">;
  RENEWAL_IDENTITY_MISMATCH: _better_auth_core_utils_error_codes0.RawError<"RENEWAL_IDENTITY_MISMATCH">;
  INVITE_NOT_FOUND: _better_auth_core_utils_error_codes0.RawError<"INVITE_NOT_FOUND">;
  INVITE_EXPIRED: _better_auth_core_utils_error_codes0.RawError<"INVITE_EXPIRED">;
  INVITE_USED: _better_auth_core_utils_error_codes0.RawError<"INVITE_USED">;
  INVITE_MISMATCH: _better_auth_core_utils_error_codes0.RawError<"INVITE_MISMATCH">;
};
//#endregion
export { DELEGATE_PERMISSIONS_ERROR_CODES };