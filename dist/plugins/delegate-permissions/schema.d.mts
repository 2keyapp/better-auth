import { DBPrimitive } from "@better-auth/core/db";

//#region src/plugins/delegate-permissions/schema.d.ts
declare const schema: {
  dpCatalogMeta: {
    fields: {
      serviceId: {
        type: "string";
        required: true;
        unique: true;
      };
      generation: {
        type: "number";
        required: true;
        defaultValue: number;
      };
      updatedAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpAction: {
    fields: {
      serviceId: {
        type: "string";
        required: true;
        index: true;
      };
      action: {
        type: "string";
        required: true;
      };
      description: {
        type: "string";
        required: false;
      };
      catalogGeneration: {
        type: "number";
        required: true;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpScopeDimension: {
    fields: {
      serviceId: {
        type: "string";
        required: true;
        index: true;
      };
      dimension: {
        type: "string";
        required: true;
      };
      algebra: {
        type: "string";
        required: true;
      };
      catalogGeneration: {
        type: "number";
        required: true;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpProfile: {
    fields: {
      serviceId: {
        type: "string";
        required: true;
        index: true;
      };
      profile: {
        type: "string";
        required: true;
      };
      permissions: {
        type: "json";
        required: true;
        transform: {
          input(value: DBPrimitive): string | number | boolean | Date | Record<string, unknown> | null | undefined;
          output(value: DBPrimitive): DBPrimitive;
        };
      };
      catalogGeneration: {
        type: "number";
        required: true;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpPrincipalGrant: {
    fields: {
      userId: {
        type: "string";
        required: true;
        index: true;
        references: {
          model: string;
          field: string;
        };
      };
      entityId: {
        type: "string";
        required: false;
      };
      permissions: {
        type: "json";
        required: true;
        transform: {
          input(value: DBPrimitive): string | number | boolean | Date | Record<string, unknown> | null | undefined;
          output(value: DBPrimitive): DBPrimitive;
        };
      };
      profile: {
        type: "string";
        required: false;
      };
      expiresAt: {
        type: "date";
        required: false;
      };
      createdAt: {
        type: "date";
        required: true;
      };
      updatedAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpSessionGrant: {
    fields: {
      sessionId: {
        type: "string";
        required: true;
        unique: true;
        index: true;
        references: {
          model: string;
          field: string;
        };
      };
      userId: {
        type: "string";
        required: true;
        index: true;
        references: {
          model: string;
          field: string;
        };
      };
      permissions: {
        type: "json";
        required: true;
        transform: {
          input(value: DBPrimitive): string | number | boolean | Date | Record<string, unknown> | null | undefined;
          output(value: DBPrimitive): DBPrimitive;
        };
      };
      expiresAt: {
        type: "date";
        required: true;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpEntity: {
    fields: {
      entityId: {
        type: "string";
        required: true;
        unique: true;
      };
      package: {
        type: "string";
        required: true;
      };
      rootSki: {
        type: "string";
        required: true;
      };
      caCertPem: {
        type: "string";
        required: false;
      };
      platformCaCertCosign: {
        type: "json";
        required: false;
      };
      ownerUserId: {
        type: "string";
        required: true;
        index: true;
        references: {
          model: string;
          field: string;
        };
      };
      createdAt: {
        type: "date";
        required: true;
      };
      updatedAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpCredential: {
    fields: {
      ski: {
        type: "string";
        required: true;
        unique: true;
      };
      entityId: {
        type: "string";
        required: true;
        index: true;
      };
      kind: {
        type: "string";
        required: true;
      };
      publicJwk: {
        type: "json";
        required: true;
      };
      credential: {
        type: "json";
        required: true;
      };
      zone: {
        type: "string";
        required: false;
      };
      host: {
        type: "string";
        required: false;
      };
      seatId: {
        type: "string";
        required: false;
      };
      status: {
        type: "string";
        required: true;
        defaultValue: string;
      };
      revokedAt: {
        type: "date";
        required: false;
      };
      revokedReason: {
        type: "string";
        required: false;
      };
      renewedBySki: {
        type: "string";
        required: false;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpUserCredentialBind: {
    fields: {
      userId: {
        type: "string";
        required: true;
        index: true;
        references: {
          model: string;
          field: string;
        };
      };
      credentialSki: {
        type: "string";
        required: true;
        index: true;
      };
      entityId: {
        type: "string";
        required: true;
        index: true;
      };
      isPrimary: {
        type: "boolean";
        required: true;
        defaultValue: true;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpNameOccupancy: {
    fields: {
      entityId: {
        type: "string";
        required: true;
        index: true;
      };
      nameKey: {
        type: "string";
        required: true;
      };
      kind: {
        type: "string";
        required: true;
      };
      credentialSki: {
        type: "string";
        required: true;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpEnrollRequest: {
    fields: {
      entityId: {
        type: "string";
        required: true;
        index: true;
      };
      host: {
        type: "string";
        required: false;
      };
      zone: {
        type: "string";
        required: false;
      };
      role: {
        type: "string";
        required: true;
      };
      csrPem: {
        type: "string";
        required: true;
      };
      subjectSki: {
        type: "string";
        required: true;
        index: true;
      };
      publicJwk: {
        type: "json";
        required: true;
      };
      status: {
        type: "string";
        required: true;
        defaultValue: string;
      };
      pullToken: {
        type: "string";
        required: true;
        unique: true;
      };
      createdByUserId: {
        type: "string";
        required: false;
      };
      leafPem: {
        type: "string";
        required: false;
      };
      chainPem: {
        type: "string";
        required: false;
      };
      credential: {
        type: "json";
        required: false;
      };
      platformCertCosign: {
        type: "json";
        required: false;
      };
      seatId: {
        type: "string";
        required: false;
      };
      createdAt: {
        type: "date";
        required: true;
      };
      updatedAt: {
        type: "date";
        required: true;
      };
    };
  };
  dpEnrollInvite: {
    fields: {
      entityId: {
        type: "string";
        required: true;
        index: true;
      };
      host: {
        type: "string";
        required: false;
      };
      zone: {
        type: "string";
        required: false;
      };
      role: {
        type: "string";
        required: true;
      };
      inviteToken: {
        type: "string";
        required: true;
        unique: true;
      };
      expiresAt: {
        type: "date";
        required: true;
      };
      maxUses: {
        type: "number";
        required: true;
        defaultValue: number;
      };
      usedCount: {
        type: "number";
        required: true;
        defaultValue: number;
      };
      consumedAt: {
        type: "date";
        required: false;
      };
      createdByUserId: {
        type: "string";
        required: false;
      };
      createdAt: {
        type: "date";
        required: true;
      };
    };
  };
};
//#endregion
export { schema };