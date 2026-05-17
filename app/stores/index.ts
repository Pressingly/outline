import RootStore from "~/stores/RootStore";
import env from "~/env";
import { checkUserContinuity } from "~/utils/userContinuity";

// Runs BEFORE RootStore is constructed so that AuthStore (and every
// other mobx-persisted store that rehydrates from localStorage in its
// constructor) sees a clean slate when the authenticated user has
// changed since the last session in this browser. See the docstring on
// `checkUserContinuity` for the full rationale.
checkUserContinuity();

const stores = new RootStore();

// Expose stores on window in development for easier debugging
if (env.ENVIRONMENT === "development") {
  window.stores = stores;
}

export default stores;
