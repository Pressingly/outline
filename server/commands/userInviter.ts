import uniqBy from "lodash/uniqBy";
import partition from "lodash/partition";
import { UserRole } from "@shared/types";
import InviteEmail from "@server/emails/templates/InviteEmail";
import env from "@server/env";
import Logger from "@server/logging/Logger";
import { User, Team } from "@server/models";
import { UserFlag } from "@server/models/User";
import type { APIContext } from "@server/types";
import { DomainNotAllowedError } from "@server/errors";
import { can } from "@server/policies";
import { Op, fn, col, where as sqlWhere } from "sequelize";

export type Invite = {
  name: string;
  email: string;
  role: UserRole;
};

type Props = {
  invites: Invite[];
  suppressEmail?: boolean;
};

export default async function userInviter(
  ctx: APIContext,
  { invites, suppressEmail }: Props
): Promise<{
  sent: Invite[];
  unsent: Invite[];
  users: User[];
}> {
  const { user } = ctx.state.auth;
  const team = await Team.findByPk(user.teamId, { rejectOnEmpty: true });

  // filter out empties and obvious non-emails
  const compactedInvites = invites.filter(
    (invite) => !!invite.email.trim() && invite.email.match("@")
  );
  // normalize to lowercase and remove duplicates
  const normalizedInvites = uniqBy(
    compactedInvites.map((invite) => ({
      ...invite,
      email: invite.email.toLowerCase(),
    })),
    "email"
  );
  // filter out any existing users in the system
  const emails = normalizedInvites.map((invite) => invite.email);

  if (!can(user, "update", team)) {
    for (const email of emails) {
      if (!(await team.isDomainAllowed(email))) {
        throw DomainNotAllowedError();
      }
    }
  }

  // Matched on lower(email), not the raw column: auth providers may capitalize
  // an address (see userProvisioner), so a stored `Foo@example.com` would be
  // invisible to an equality test against the lowercased invite list. The
  // users_team_id_email_unique index keys on lower(email), so missing one here
  // means the create below raises a constraint violation instead of the address
  // landing in the `existing` bucket where it belongs.
  const existingUsers = await User.findAll({
    where: {
      teamId: user.teamId,
      [Op.and]: [sqlWhere(fn("lower", col("email")), { [Op.in]: emails })],
    },
  });
  // `emails` is already lowercased above, so only the stored side needs
  // normalizing for the membership test below.
  const existingEmails = existingUsers.map((existingUser) =>
    existingUser.email?.toLowerCase()
  );
  const [existingInvites, filteredInvites] = partition(
    normalizedInvites,
    (invite) => existingEmails.includes(invite.email)
  );
  const users = [];

  // send and record remaining invites
  for (const invite of filteredInvites) {
    const newUser = await User.createWithCtx(
      ctx,
      {
        teamId: user.teamId,
        name: invite.name,
        email: invite.email,
        role:
          user.isAdmin && invite.role === UserRole.Admin
            ? UserRole.Admin
            : user.isViewer || invite.role === UserRole.Viewer
              ? UserRole.Viewer
              : UserRole.Member,
        invitedById: user.id,
        flags: suppressEmail
          ? undefined
          : {
              [UserFlag.InviteSent]: 1,
            },
      },
      {
        name: "invite",
      }
    );
    users.push(newUser);

    if (!suppressEmail) {
      await new InviteEmail({
        to: invite.email,
        language: newUser.language,
        name: invite.name,
        actorName: user.name,
        actorEmail: user.email,
        teamName: team.name,
        teamUrl: team.url,
      }).schedule();
    }

    if (env.isDevelopment) {
      Logger.info(
        "email",
        `Sign in immediately: ${
          env.URL
        }/auth/email.callback?token=${newUser.getEmailSigninToken(ctx)}`
      );
    }
  }

  return {
    sent: filteredInvites,
    unsent: existingInvites,
    users,
  };
}
