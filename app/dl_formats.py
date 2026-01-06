import copy

AUDIO_FORMATS = ("m4a", "mp3", "opus", "wav", "flac")


def get_format(format: str, quality: str) -> str:
    """
    Returns format for download

    Args:
      format (str): format selected
      quality (str): quality selected

    Raises:
      Exception: unknown quality, unknown format

    Returns:
      dl_format: Formatted download string
    """
    import logging
    log = logging.getLogger('dl_formats')
    original_format = format
    format = format or "any"
    log.info(f'get_format called with format="{original_format}" (normalized to "{format}"), quality="{quality}"')

    if format.startswith("custom:"):
        return format[7:]

    if format == "thumbnail":
        # Quality is irrelevant in this case since we skip the download
        return "bestaudio/best"

    if format in AUDIO_FORMATS:
        # Audio quality needs to be set post-download, set in opts
        result = f"bestaudio[ext={format}]/bestaudio/best"
        log.info(f'Audio format detected ({format}), returning: {result}')
        return result

    if format in ("mp4", "any"):
        if quality == "audio":
            return "bestaudio/best"
        # video {res} {vfmt} + audio {afmt} {res} {vfmt}
        vfmt, afmt = ("[ext=mp4]", "[ext=m4a]") if format == "mp4" else ("", "")
        vres = f"[height<={quality}]" if quality not in ("best", "best_ios", "worst") else ""
        vcombo = vres + vfmt

        if quality == "best_ios":
            # iOS has strict requirements for video files, requiring h264 or h265
            # video codec and aac audio codec in MP4 container. This format string
            # attempts to get the fully compatible formats first, then the h264/h265
            # video codec with any M4A audio codec (because audio is faster to
            # convert if needed), and falls back to getting the best available MP4
            # file.
            return f"bestvideo[vcodec~='^((he|a)vc|h26[45])']{vres}+bestaudio[acodec=aac]/bestvideo[vcodec~='^((he|a)vc|h26[45])']{vres}+bestaudio{afmt}/bestvideo{vcombo}+bestaudio{afmt}/best{vcombo}"
        result = f"bestvideo{vcombo}+bestaudio{afmt}/best{vcombo}"
        log.info(f'Video format detected (format={format}, quality={quality}), returning: {result}')
        return result

    log.error(f'Unknown format: {format}')
    raise Exception(f"Unknown format {format}")


def get_opts(format: str, quality: str, ytdl_opts: dict, download_subtitles: bool = False, download_thumbnails: bool = True) -> dict:
    """
    Returns extra download options
    Mostly postprocessing options

    Args:
      format (str): format selected
      quality (str): quality of format selected (needed for some formats)
      ytdl_opts (dict): current options selected
      download_subtitles (bool): whether to download subtitles
      download_thumbnails (bool): whether to download/embed thumbnails

    Returns:
      ytdl_opts: Extra options
    """
    import logging
    log = logging.getLogger('dl_formats')

    opts = copy.deepcopy(ytdl_opts)

    postprocessors = []

    # ONLY add FFmpegExtractAudio for actual audio formats
    # Make sure format is NOT a video format
    if format in AUDIO_FORMATS:
        log.info(f'Adding FFmpegExtractAudio postprocessor for audio format: {format}')
        postprocessors.append(
            {
                "key": "FFmpegExtractAudio",
                "preferredcodec": format,
                "preferredquality": 0 if quality == "best" else quality,
            }
        )

        # Audio formats with thumbnail (if enabled and format supports it)
        if download_thumbnails and format not in ("wav") and "writethumbnail" not in opts:
            opts["writethumbnail"] = True
            postprocessors.append(
                {
                    "key": "FFmpegThumbnailsConvertor",
                    "format": "jpg",
                    "when": "before_dl",
                }
            )
            postprocessors.append({"key": "FFmpegMetadata"})
            postprocessors.append({"key": "EmbedThumbnail"})
    else:
        log.info(f'NOT adding FFmpegExtractAudio for format: {format} (not an audio-only format)')

    if format == "thumbnail":
        opts["skip_download"] = True
        opts["writethumbnail"] = True
        postprocessors.append(
            {"key": "FFmpegThumbnailsConvertor", "format": "jpg", "when": "before_dl"}
        )

    # Subtitle options
    if download_subtitles:
        opts["writesubtitles"] = True
        opts["writeautomaticsub"] = True  # Also get auto-generated subtitles
        opts["subtitleslangs"] = ["de", "en"]  # German and English only
        opts["subtitlesformat"] = "best"
        # Don't fail if subtitles are unavailable
        opts["ignoreerrors"] = "only_download"
        # Embed subtitles into video if it's a video format
        if format not in AUDIO_FORMATS and format != "thumbnail":
            postprocessors.append({"key": "FFmpegEmbedSubtitle"})

    # Merge with existing postprocessors from YTDL_OPTIONS, but filter out
    # FFmpegExtractAudio for video formats to prevent audio extraction
    existing_postprocessors = opts.get("postprocessors", [])
    
    # If we have a video format (not audio), remove FFmpegExtractAudio from existing postprocessors
    if format not in AUDIO_FORMATS and format != "thumbnail":
        filtered_count = len(existing_postprocessors)
        existing_postprocessors = [
            pp for pp in existing_postprocessors 
            if isinstance(pp, dict) and pp.get("key") != "FFmpegExtractAudio"
        ]
        if len(existing_postprocessors) != filtered_count:
            log.info(f'Filtered out FFmpegExtractAudio from YTDL_OPTIONS for video format: {format}')
    
    opts["postprocessors"] = postprocessors + existing_postprocessors
    log.info(f'Final postprocessors for format {format}: {[pp.get("key") if isinstance(pp, dict) else str(pp) for pp in opts["postprocessors"]]}')
    return opts
