# ---------------------------------------
# jupyter
# ---------------------------------------

function bh_jupyter_notebook() {
  jupyter notebook
}

function bh_jupyter_remove_output() {
  jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace $@
}
