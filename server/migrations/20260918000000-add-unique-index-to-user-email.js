"use strict";

/**
 * One live user per email address, per team.
 *
 * Upstream Outline has only a non-unique `users_email` index, so nothing stops
 * two rows sharing an address. On this deployment that produced real duplicates:
 * a just-in-time provisioning race created five rows for one address inside
 * 97ms, and every duplicate had to be merged by hand.
 *
 * Scoped to ("teamId", lower(email)) rather than email alone:
 *   - teamId because Outline is multi-tenant and the same person may legitimately
 *     exist in two teams.
 *   - lower(email) because Outline resolves users with `Op.iLike` (see
 *     server/commands/userProvisioner.ts), so two rows differing only in case are
 *     the same user to the application and must not both be insertable.
 *
 * Partial on `"deletedAt" IS NULL` because Outline soft-deletes: a retired
 * account keeps its address forever, and this deployment has 13 addresses held
 * by a deleted row alongside the live one. A full index would fail to build and,
 * once built, would stop a retired address from ever being reused.
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE UNIQUE INDEX "users_team_id_email_unique"
        ON "users" ("teamId", lower("email"))
        WHERE "deletedAt" IS NULL
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS "users_team_id_email_unique"
    `);
  },
};
