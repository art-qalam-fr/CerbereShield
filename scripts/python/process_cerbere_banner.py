"""
Script de traitement et d'optimisation haute-fidelite pour la banniere Cerbere Security Shield.
Traite logo/b7c206b6-dc42-431a-ad9d-3482bde2da68.jpg -> web_port_dashboard/static/img/cerbere_banner.png
Genere un apercu composite sur fond #0f172a dans %TEMP%/banner_preview.jpg.
"""

import os
import sys
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

def process_banner(
    src_path: str,
    dst_png_path: str,
    preview_jpg_path: str,
    y_crop_start: int = 48,
    y_crop_end: int = 548,
    fade_percent: float = 0.15
):
    print(f"[+] Chargement de l'image source : {src_path}")
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Source introuvable : {src_path}")

    # Lecture via OpenCV (BGR)
    src_bgr = cv2.imread(src_path)
    if src_bgr is None:
        raise ValueError(f"Impossible de lire l'image : {src_path}")

    h, w = src_bgr.shape[:2]
    print(f"    Dimensions source : {w}x{h}")

    # Analyse chromatique et de luminance
    b, g, r = src_bgr.astype(np.int32)[:, :, 0], src_bgr.astype(np.int32)[:, :, 1], src_bgr.astype(np.int32)[:, :, 2]
    chroma = np.maximum(np.maximum(np.abs(b - g), np.abs(b - r)), np.abs(g - r))
    gray = cv2.cvtColor(src_bgr, cv2.COLOR_BGR2GRAY)

    # 1. Detection du damier d'arriere-plan (checkerboard)
    # Dans le damier JPEG, les pixels sont neutres (chroma <= 4) et de haute luminance (gray >= 180).
    is_bg_candidate = (chroma <= 4) & (gray >= 180)

    num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(
        is_bg_candidate.astype(np.uint8), connectivity=8
    )

    # Identifier les composantes connectees aux bordures superieures et inferieures (fond externe)
    top_labels = set(np.unique(labels[0, :]))
    bottom_labels = set(np.unique(labels[-1, :]))
    exterior_labels = top_labels.union(bottom_labels)

    bg_mask = np.zeros((h, w), dtype=bool)
    for lbl in range(1, num_labels):
        if lbl in exterior_labels:
            bg_mask |= (labels == lbl)
        else:
            # Composante interieure : verifier si c'est un trou de lettre / interstice du damier
            # Un damier transparent contient a la fois des carreaux gris (~195) et blancs (~255)
            ys, xs = np.where(labels == lbl)
            g_vals = gray[ys, xs]
            if np.min(g_vals) <= 205 and np.max(g_vals) >= 248 and len(ys) >= 15:
                bg_mask |= (labels == lbl)

    fg_mask = ~bg_mask

    # 2. Nettoyage des artefacts JPEG (mosquito noise / ringing dans le damier)
    # Les petits paquets isoles (< 50 px) ayant une luminance elevee et une tres faible saturation
    num_fg, fg_labels, fg_stats, _ = cv2.connectedComponentsWithStats(
        fg_mask.astype(np.uint8), connectivity=8
    )
    specks_cleaned = 0
    for lbl in range(1, num_fg):
        area = fg_stats[lbl, cv2.CC_STAT_AREA]
        if area < 50:
            ys, xs = np.where(fg_labels == lbl)
            m_chroma = np.mean(chroma[ys, xs])
            m_gray = np.mean(gray[ys, xs])
            if m_gray >= 170 and m_chroma <= 8:
                fg_mask[ys, xs] = False
                bg_mask[ys, xs] = True
                specks_cleaned += 1

    print(f"    Artefacts JPEG nettoyes en arriere-plan : {specks_cleaned} paquets isoles")

    # 3. Recadrage vertical pour eliminer les marges vides tout en preservant l'artwork integral
    # y=48 a 548 donne une hauteur exacte de 500 px (ratio ~ 1024x500)
    print(f"[+] Recadrage vertical : y=[{y_crop_start}, {y_crop_end}], hauteur={y_crop_end - y_crop_start}px")
    crop_bgr = src_bgr[y_crop_start:y_crop_end, :]
    crop_fg = fg_mask[y_crop_start:y_crop_end, :]

    ch, cw = crop_bgr.shape[:2]

    # 4. Construction et adoucissement de l'alpha (Anti-aliasing sub-pixel)
    alpha_base = np.where(crop_fg, 255.0, 0.0).astype(np.float32)

    # Masques d'erosion pour identifier le coeur certain du premier plan et de l'arriere-plan
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
    fg_core = cv2.erode((alpha_base == 255).astype(np.uint8), kernel)
    bg_core = cv2.erode((alpha_base == 0).astype(np.uint8), kernel)

    # Flou gaussien sub-pixel sur la bordure de transition uniquement
    alpha_blurred = cv2.GaussianBlur(alpha_base, (3, 3), 0.75)
    alpha_refined = np.where(fg_core == 1, 255.0, np.where(bg_core == 1, 0.0, alpha_blurred))

    # 5. Fondu progressif (fade out) sur 15% des bords gauche et droit
    fade_len = int(cw * fade_percent)
    print(f"[+] Application du fondu lateral progressif sur {fade_len}px (~{int(fade_percent*100)}% de chaque cote)")
    fade_x = np.ones(cw, dtype=np.float32)
    if fade_len > 0:
        # Courbe cosinusoïdale lisse C1 continue (0 a 1)
        t = np.linspace(0.0, 1.0, fade_len)
        cosine_curve = 0.5 * (1.0 - np.cos(np.pi * t))
        fade_x[:fade_len] = cosine_curve
        fade_x[-fade_len:] = cosine_curve[::-1]

    alpha_final = (alpha_refined * fade_x[np.newaxis, :]).clip(0.0, 255.0).astype(np.uint8)

    # 6. Assemblage du PNG RGBA 32-bit
    b_chan, g_chan, r_chan = cv2.split(crop_bgr)
    rgba = cv2.merge([b_chan, g_chan, r_chan, alpha_final])

    os.makedirs(os.path.dirname(os.path.abspath(dst_png_path)), exist_ok=True)
    cv2.imwrite(dst_png_path, rgba, [cv2.IMWRITE_PNG_COMPRESSION, 9])
    png_size = os.path.getsize(dst_png_path)
    print(f"[OK] PNG transparent sauvegarde : {dst_png_path} ({cw}x{ch}, {png_size:,} octets)")

    # 7. Composition de previsualisation sur fond sombre #0f172a
    # #0f172a en BGR : [42, 23, 15]
    bg_color = np.array([42, 23, 15], dtype=np.float32)
    alpha_norm = (alpha_final.astype(np.float32) / 255.0)[:, :, np.newaxis]
    comp_bgr = (crop_bgr.astype(np.float32) * alpha_norm + bg_color * (1.0 - alpha_norm))
    comp_bgr = comp_bgr.clip(0, 255).astype(np.uint8)

    os.makedirs(os.path.dirname(os.path.abspath(preview_jpg_path)), exist_ok=True)
    cv2.imwrite(preview_jpg_path, comp_bgr, [cv2.IMWRITE_JPEG_QUALITY, 95])
    preview_size = os.path.getsize(preview_jpg_path)
    print(f"[OK] Apercu JPG sauvegarde : {preview_jpg_path} ({preview_size:,} octets)")

    return {
        "width": cw,
        "height": ch,
        "png_path": dst_png_path,
        "png_size": png_size,
        "preview_path": preview_jpg_path,
        "preview_size": preview_size,
        "specks_cleaned": specks_cleaned
    }

if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[2]
    src = str(repo / "logo" / "b7c206b6-dc42-431a-ad9d-3482bde2da68.jpg")
    dst = str(repo / "web_port_dashboard" / "static" / "img" / "cerbere_banner.png")
    temp_dir = os.environ.get("TEMP", r"C:\Users\Administrator\AppData\Local\Temp")
    preview = os.path.join(temp_dir, "banner_preview.jpg")

    res = process_banner(src, dst, preview)
    print("\nResultat du traitement :", res)
