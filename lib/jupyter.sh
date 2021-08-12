# ---------------------------------------
# jupyter
# ---------------------------------------

function hf_jupyter_notebook() {
  jupyter notebook
}

function hf_jupyter_remove_output() {
  jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace $@
}
