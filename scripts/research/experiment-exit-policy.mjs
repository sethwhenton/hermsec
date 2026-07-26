export function classifyExperimentExit(result) {
  const failedCells = result.cells.filter(
    (cell) => cell.status === "failed" || cell.status === "canceled",
  );
  const liveNonSuccessCells =
    result.execution === "live"
      ? result.cells.filter((cell) => cell.status !== "success")
      : [];
  const liveNonSucceededPhysicalModelCalls =
    result.execution === "live"
      ? result.cells
          .filter((cell) => cell.physical)
          .flatMap((cell) =>
            cell.modelCallTrace.calls.filter(
              (call) => call.terminalState !== "succeeded",
            ),
          )
      : [];
  return {
    failedCells,
    liveNonSuccessCells,
    liveNonSucceededPhysicalModelCalls,
    exitCode:
      failedCells.length > 0 ||
      liveNonSuccessCells.length > 0 ||
      liveNonSucceededPhysicalModelCalls.length > 0
        ? 2
        : 0,
  };
}
