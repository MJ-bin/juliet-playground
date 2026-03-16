from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import scienceplots  # noqa: F401
from transformers import RobertaTokenizer

MAX_LENGTH = 512
CONTENT_TOKEN_LIMIT = MAX_LENGTH - 2


def load_tokenizer(model_name: str) -> RobertaTokenizer:
    try:
        return RobertaTokenizer.from_pretrained(model_name, local_files_only=True)
    except Exception:
        print(
            f'Local tokenizer cache not found for {model_name}; trying remote download...',
            file=sys.stderr,
        )
        try:
            return RobertaTokenizer.from_pretrained(model_name)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load tokenizer '{model_name}'. "
                f'Ensure the model is cached locally or network access is available.'
            ) from exc


def count_code_tokens(tokenizer: RobertaTokenizer, code: str) -> int:
    return len(tokenizer.tokenize(str(code)))


def plot_distribution(results: list[dict[str, Any]], output_plot: Path | str) -> None:
    plt.style.use(['science', 'no-latex'])
    fig, ax = plt.subplots(figsize=(8, 5))

    if not results:
        ax.text(0.5, 0.5, 'No slice files found', ha='center', va='center', transform=ax.transAxes)
        ax.set_axis_off()
    else:
        token_counts = [int(row['code_token_count']) for row in results]
        ax.hist(
            token_counts,
            bins=min(50, max(10, len(set(token_counts)))),
            edgecolor='black',
            alpha=0.7,
        )
        ax.set_xlabel('Token Count')
        ax.set_ylabel('Number of Slices')
        ax.set_title('Token Count Distribution of Generated Slices')

        avg = sum(token_counts) / len(token_counts)
        sorted_counts = sorted(token_counts)
        median = sorted_counts[len(sorted_counts) // 2]
        stats_text = f'Total: {len(token_counts)}\nMean: {avg:.1f}\nMedian: {median}'
        ax.text(
            0.95,
            0.95,
            stats_text,
            transform=ax.transAxes,
            fontsize=9,
            verticalalignment='top',
            horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5),
        )

    fig.tight_layout()
    fig.savefig(output_plot, dpi=200)
    plt.close(fig)


__all__ = [
    'CONTENT_TOKEN_LIMIT',
    'MAX_LENGTH',
    'count_code_tokens',
    'load_tokenizer',
    'plot_distribution',
]
