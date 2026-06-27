# HermSec Parallel Subagent Fixture Matrix

Generated: 2026-06-27T15:12:06.949Z
Output root: <hermsec-repo>\.hermsec\model-test-runs\parallel-20260627-subagents

> Note: All three modes were run by subagents. Deep-assisted report artifacts completed, but its model phase fell back; scoring uses completed reports while preserving run-level `ok:false`.

## Mode Summary

| Mode | Runs | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deep-assisted | 4 | 8 | 81 | 4 | 0.0899 | 0.6667 | 0.1584 |
| single-agent | 4 | 2 | 1 | 10 | 0.6667 | 0.1667 | 0.2667 |
| moa-assisted | 4 | 5 | 4 | 7 | 0.5556 | 0.4167 | 0.4762 |

## Run Details

| Fixture | Mode | Report completed | Model fallback | Findings | Expected | TP | FP | FN | Precision | Recall | F1 | Duration s |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| node-express-vulnerable | deep-assisted | true | true | 25 | 6 | 3 | 22 | 3 | 0.12 | 0.5 | 0.1935 | 66.2 |
| node-express-clean | deep-assisted | true | true | 6 | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 54.0 |
| python-flask-vulnerable | deep-assisted | true | true | 57 | 6 | 5 | 52 | 1 | 0.0877 | 0.8333 | 0.1587 | 122.3 |
| python-flask-clean | deep-assisted | true | true | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 27.2 |
| node-express-vulnerable | single-agent | true | false | 2 | 6 | 1 | 1 | 5 | 0.5 | 0.1667 | 0.25 | 14.1 |
| node-express-clean | single-agent | true | false | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 7.0 |
| python-flask-vulnerable | single-agent | true | false | 1 | 6 | 1 | 0 | 5 | 1 | 0.1667 | 0.2858 | 9.1 |
| python-flask-clean | single-agent | true | false | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 5.0 |
| node-express-vulnerable | moa-assisted | true | false | 6 | 6 | 3 | 3 | 3 | 0.5 | 0.5 | 0.5 | 93.2 |
| node-express-clean | moa-assisted | true | false | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 14.0 |
| python-flask-vulnerable | moa-assisted | true | false | 3 | 6 | 2 | 1 | 4 | 0.6667 | 0.3333 | 0.4444 | 62.1 |
| python-flask-clean | moa-assisted | true | false | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 18.0 |

