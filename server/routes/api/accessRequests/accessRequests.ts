import Router from "koa-router";
import auth from "@server/middlewares/authentication";
import { rateLimiter } from "@server/middlewares/rateLimiter";
import { transaction } from "@server/middlewares/transaction";
import validate from "@server/middlewares/validate";
import { Document, AccessRequest, UserMembership, Event } from "@server/models";
import { AccessRequestStatus } from "@server/models/AccessRequest";
import { authorize } from "@server/policies";
import { presentAccessRequest, presentPolicies } from "@server/presenters";
import type { APIContext } from "@server/types";
import { RateLimiterStrategy } from "@server/utils/RateLimiter";
import * as T from "./schema";
import {
  DocumentPermissionPriority,
  getDocumentPermission,
} from "@server/utils/permissions";
import {
  AuthorizationError,
  InvalidRequestError,
  NotFoundError,
} from "@server/errors";

const router = new Router();

router.post(
  "accessRequests.create",
  rateLimiter(RateLimiterStrategy.TwentyFivePerMinute),
  auth(),
  validate(T.AccessRequestsCreateSchema),
  transaction(),
  async (ctx: APIContext<T.AccessRequestsCreateReq>) => {
    const { documentId } = ctx.input.body;
    const { user } = ctx.state.auth;
    const { transaction } = ctx.state;

    const document = await Document.findByPk(documentId, {
      userId: user.id,
      transaction,
      rejectOnEmpty: true,
    });
    authorize(user, "read", document);

    const accessRequest = await AccessRequest.createWithCtx(ctx, {
      documentId: document.id,
      teamId: document.teamId,
      userId: user.id,
      status: AccessRequestStatus.Pending,
    });

    await Event.createFromContext(ctx, {
      name: "documents.request_access",
      documentId: document.id,
    });

    ctx.body = {
      data: presentAccessRequest(accessRequest),
      policies: presentPolicies(user, [accessRequest]),
    };
  }
);

router.post(
  "accessRequests.info",
  rateLimiter(RateLimiterStrategy.TwentyFivePerMinute),
  auth(),
  validate(T.AccessRequestsInfoSchema),
  async (ctx: APIContext<T.AccessRequestsInfoReq>) => {
    const { user } = ctx.state.auth;
    const { id, documentId } = ctx.input.body;

    let accessReq: AccessRequest | null;

    if (id) {
      accessReq = await AccessRequest.findByPk(id);
    } else {
      const document = await Document.findByPk(documentId!, {
        userId: user.id,
      });
      accessReq = document
        ? await AccessRequest.pendingRequest({
            documentId: document.id,
            userId: user.id,
          })
        : null;
    }

    if (!accessReq) {
      throw NotFoundError("Access request not found");
    }
    authorize(user, "read", accessReq);

    ctx.body = {
      data: presentAccessRequest(accessReq),
      policies: presentPolicies(user, [accessReq]),
    };
  }
);

router.post(
  "accessRequests.approve",
  rateLimiter(RateLimiterStrategy.TwentyFivePerMinute),
  auth(),
  validate(T.AccessRequestsApproveSchema),
  transaction(),
  async (ctx: APIContext<T.AccessRequestsApproveReq>) => {
    const { id, permission } = ctx.input.body;
    const { user } = ctx.state.auth;
    const { transaction } = ctx.state;

    const accessRequest = await AccessRequest.unscoped().findByPk(id, {
      rejectOnEmpty: true,
      transaction,
      lock: { level: transaction.LOCK.UPDATE, of: AccessRequest },
    });
    authorize(user, "update", accessRequest);

    if (accessRequest.status !== AccessRequestStatus.Pending) {
      throw InvalidRequestError("Access request has already been responded to");
    }

    const document = await Document.findByPk(accessRequest.documentId, {
      userId: user.id,
      transaction,
    });
    authorize(user, "share", document);

    const adminPermission = await getDocumentPermission({
      userId: user.id,
      documentId: document.id,
    });
    if (
      !adminPermission ||
      DocumentPermissionPriority[permission] >
        DocumentPermissionPriority[adminPermission]
    ) {
      throw AuthorizationError();
    }

    const membership = await UserMembership.findOne({
      where: {
        userId: accessRequest.userId,
        documentId: accessRequest.documentId,
      },
      lock: transaction.LOCK.UPDATE,
      transaction,
    });

    if (membership) {
      throw InvalidRequestError("User already has access to the document");
    }
    await UserMembership.createWithCtx(ctx, {
      userId: accessRequest.userId,
      documentId: accessRequest.documentId,
      permission: permission,
      createdById: user.id,
    });

    accessRequest.approve(user.id);
    await accessRequest.saveWithCtx(ctx);

    ctx.body = {
      data: presentAccessRequest(accessRequest),
      policies: presentPolicies(user, [accessRequest]),
    };
  }
);

router.post(
  "accessRequests.dismiss",
  rateLimiter(RateLimiterStrategy.TwentyFivePerMinute),
  auth(),
  validate(T.AccessRequestsDismissSchema),
  transaction(),
  async (ctx: APIContext<T.AccessRequestsDismissReq>) => {
    const { id } = ctx.input.body;
    const { user } = ctx.state.auth;
    const { transaction } = ctx.state;

    const accessRequest = await AccessRequest.unscoped().findByPk(id, {
      rejectOnEmpty: true,
      transaction,
      lock: { level: transaction.LOCK.UPDATE, of: AccessRequest },
    });
    authorize(user, "update", accessRequest);

    if (accessRequest.status !== AccessRequestStatus.Pending) {
      throw InvalidRequestError("Access request has already been responded to");
    }

    const document = await Document.findByPk(accessRequest.documentId, {
      userId: user.id,
      transaction,
    });
    authorize(user, "share", document);

    accessRequest.dismiss(user.id);
    await accessRequest.saveWithCtx(ctx);

    ctx.body = {
      data: presentAccessRequest(accessRequest),
      policies: presentPolicies(user, [accessRequest]),
    };
  }
);

export default router;
