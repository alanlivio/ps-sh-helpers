function pandoc_dir_extension_conv() {
    : ${2?"Usage: ${FUNCNAME[0]} <extension_from> <extension_to>"}
    for i in *."$1"; do
        pandoc -i $i -o ${i%.*}."$2"
    done
}
