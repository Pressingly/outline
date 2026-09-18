"use strict";

/** @type {import('sequelize-cli').Migration} */

/**
 * One live user per email address, per team.
 *
 * Upstream Outline has only a non-unique `users_email` index, so nothing stops
 * two rows sharing an address. On this deployment that produced real duplicates:
 * a just-in-time provisioning race created five rows for one address inside
 * 97ms, and twelve further duplicates had to be merged by hand.
 *
 * Scoped to ("teamId", lower(email)) rather than email alone:
 *   - teamId because `User.availableTeams()` deliberately matches one address
 *     across teams, so global uniqueness would break account switching.
 *   - lower(email) because Outline resolves users with `Op.iLike` (see
 *     server/commands/userProvisioner.ts) and auth providers may capitalize the
 *     address, so two rows differing only in case are the same user to the
 *     application and must not both be insertable.
 *
 * Partial on `"deletedAt" IS NULL` because rows soft-deleted OUTSIDE the model
 * hooks keep their address. `User.removeIdentifyingInfo` (@BeforeDestroy) nulls
 * `email` on an ordinary delete, and NULLs never collide in a unique index — but
 * a direct `UPDATE users SET "deletedAt"` bypasses it, and this deployment has
 * 20 such rows from the manual duplicate merges. Without the predicate the index
 * would not build against them, and once built it would stop their addresses
 * from ever being reused.
 */
module.exports = {
  async up(queryInterface) {
    // Fail with the offending rows rather than Postgres' first-conflict-only
    // error. Another deployment of this fork may carry live duplicates, and
    // `db:migrate` aborting there would block every later migration with no
    // indication of what to merge.
    const [conflicts] = await queryInterface.sequelize.query(`
      SELECT "teamId", lower("email") AS email, count(*) AS rows
        FROM "users"
       WHERE "deletedAt" IS NULL AND "email" IS NOT NULL
       GROUP BY "teamId", lower("email")
      HAVING count(*) > 1
       ORDER BY count(*) DESC
    `);

    if (conflicts.length > 0) {
      const detail = conflicts
        .map((c) => `  ${c.email} (teamId ${c.teamId}): ${c.rows} rows`)
        .join("\n");
      throw new Error(
        "Cannot add users_team_id_email_unique: these addresses are held by " +
          `more than one live user and must be merged first.\n${detail}\n` +
          "Move each duplicate's content onto the account you are keeping, " +
          'soft-delete the others (UPDATE "users" SET "deletedAt" = now()), ' +
          "then re-run this migration."
      );
    }

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
