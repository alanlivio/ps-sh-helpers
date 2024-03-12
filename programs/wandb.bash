function wandb_clean() {
    wandb sync --clean-force
}

function wandb_del_all_runs_from_project() {
    : ${2?"Usage: ${FUNCNAME[0]} <entity_name> <project_name>"}
    python - <<-EOF
import wandb
api = wandb.Api()
runs = api.runs('$1/$2')
for run in runs:
    for artifact in run.logged_artifacts():
        artifact.delete()
    run.delete()
EOF
}
