function ffmpeg_cut_mp4 {
    param(
        [Parameter(Mandatory = $true)][string]$video,
        [Parameter(Mandatory = $true)][string]$beginTime,
        [Parameter(Mandatory = $true)][string]$endTime
    )
    $fname_no_ext = [System.IO.Path]::GetFileNameWithoutExtension($video)
    $extension = [System.IO.Path]::GetExtension($video)
    ffmpeg.exe -i "$video" -vcodec copy -acodec copy -ss "$beginTime" -t "$endTime" -f mp4 "$fname_no_ext (cuted)$extension"
}

function ffmpeg_convert_to_mp4_960x540 {
    param(
        [Parameter(Mandatory = $true)][string]$video
    )
    $fname_no_ext = [System.IO.Path]::GetFileNameWithoutExtension($video)
    ffmpeg.exe -i "$video" -vf "scale=960:540" -c:v libx264 -c:a aac "$fname_no_ext (converted).mp4"
}

function ffmpeg_convert_to_mp4_960x540_cutted_until {
    param(
        [Parameter(Mandatory = $true)][string]$video,

        [Parameter(Mandatory = $true)][string]$cutUntilTime
    )
    $fname_no_ext = [System.IO.Path]::GetFileNameWithoutExtension($video)
    ffmpeg.exe -i "$video" -ss 00:00:00 -t "$cutUntilTime" -vf "scale=960:540" -c:v libx264 -c:a aac "$fname_no_ext (converted).mp4"
}

function ffmpeg_extract_audio_m4a {
    param(
        [Parameter(Mandatory = $true)][string]$video
    )
    $fname_no_ext = [System.IO.Path]::GetFileNameWithoutExtension($video)
    ffmpeg.exe -i "$video" -vn -acodec copy "$fname_no_ext (audio only).m4a"
}

function ffmpeg_extract_video_mp4 {
    param(
        [Parameter(Mandatory = $true)][string]$video
    )
    $fname_no_ext = [System.IO.Path]::GetFileNameWithoutExtension($video)
    ffmpeg.exe -i "$video" -c:v copy -an "$fname_no_ext (video only).mp4"
}

function ffmpeg_show_motion_vectors {
    param(
        [Parameter(Mandatory = $true)][string]$video
    )
    ffplay.exe -flags2 +export_mvs -vf codecview=mv=pf+bf+bb "$video"
}

function ffmpeg_extract_key_frames {
    param(
        [Parameter(Mandatory = $true)][string]$video
    )
    $fname_no_ext = [System.IO.Path]::GetFileNameWithoutExtension($video)
    ffmpeg.exe -skip_frame nokey -i "$video" -vsync vfr -frame_pts true "${fname_no_ext}-key-frame-%02d.jpeg"
}

function ffmpeg_mp4_files_merge {
    param(
        [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$files
    )
    $fileList = $files | ForEach-Object { "file '$((Resolve-Path $_).Path)'" }
    $tempFile = [System.IO.Path]::GetTempFileName() + ".txt"
    $fileList | Set-Content $tempFile
    ffmpeg.exe -f concat -safe 0 -i "$tempFile" -c copy merged.mp4
    Remove-Item $tempFile
}