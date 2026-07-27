type DoctorSmokeGroup = {
  id: string;
  status: string;
  message?: string;
};

type DoctorSmokeResult = {
  ok: boolean;
  runtimeReady: boolean;
  status: "ready" | "attention" | "blocked";
  groups: readonly DoctorSmokeGroup[];
};

export function createPackagedDoctorSmokeResult<
  Result extends DoctorSmokeResult,
>(result: Result): Result {
  const required = result.groups.find(
    (group) => group.id === "required",
  );
  const scanners = result.groups.find(
    (group) => group.id === "scanners",
  );
  if (!result.runtimeReady) {
    throw new Error(
      "Hermsec's packaged CLI runtime is not ready.",
    );
  }
  if (required?.status !== "pass") {
    throw new Error(
      `Required checks are not ready: ${required?.message ?? "missing group"}`,
    );
  }
  if (scanners?.status !== "pass") {
    throw new Error(
      `Scanner checks are not ready: ${scanners?.message ?? "missing group"}`,
    );
  }

  // Release health verifies the self-contained runtime, not transient access
  // to third-party endpoints on a CI runner. Connectivity and provider
  // diagnostics remain in the result without invalidating the packaged build.
  return {
    ...result,
    ok: true,
    status:
      result.status === "blocked" ? "attention" : result.status,
  };
}
