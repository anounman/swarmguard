# SwarmGuard loop (PLAN §5). Override dirs for offline/fake trees: make metrics RUNS=/tmp/x/runs RESULTS=/tmp/x/results
ITER ?= 0
RUNS ?= runs
RESULTS ?= results
LOOPDIR ?= loop
TRAIN ?= train
L = uv run python -m loop.loop --iter $(ITER) --runs $(RUNS) --results $(RESULTS) --loopdir $(LOOPDIR) --train-dir $(TRAIN)

.PHONY: loop smoke bench metrics compare harvest retrain report test dry-run
loop: ; $(L) --stage all
smoke: ; $(L) --stage smoke
bench: ; $(L) --stage bench
dry-run: ; $(L) --stage all --dry-run   # plan + budget-gate decision per cell; launches nothing
metrics: ; $(L) --stage metrics
compare: ; $(L) --stage compare
harvest: ; $(L) --stage harvest
retrain: ; $(L) --stage retrain
report: ; uv run python docs/render.py --metrics $(RESULTS)/metrics.json
test: ; uv run pytest -q
