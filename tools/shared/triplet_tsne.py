from __future__ import annotations

import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import matplotlib
import numpy as np

from shared.fs import prepare_output_dir
from shared.jsonio import write_json, write_jsonl

matplotlib.use('Agg')


TRIPLET_BASENAME = 'triplet_test_last_hidden_state_vectors'
PDBERT_PREDICTION_KIND = 'pdbert'
LINEVUL_PREDICTION_KIND = 'linevul'
TRIPLET_CLASS_NAMES = {
    0: 'Patched (Non-Vulnerable)',
    1: 'Vulnerable',
}
DEFAULT_TSNE_FIGSIZE = (11, 10)
DEFAULT_TSNE_SHUFFLE_SEED = 0
DEFAULT_TSNE_MARKER_LINEWIDTH = 0.9
DEFAULT_TSNE_COLOR_LEGEND_Y = 1.13
DEFAULT_TSNE_MARKER_LEGEND_Y = 1.05
DEFAULT_TSNE_LAYOUT_TOP = 0.82
DEFAULT_TSNE_PAIR_LINK_COLOR = '#4d4d4d'
DEFAULT_TSNE_PAIR_LINK_ALPHA = 0.45
DEFAULT_TSNE_PAIR_LINK_LINEWIDTH = 1.0
DEFAULT_TSNE_CVE_PATCHED_SIZE_SCALE = 1.28
DEFAULT_TSNE_CVE_VULNERABLE_SIZE_SCALE = 0.86
DEFAULT_TSNE_CVE_PATCHED_LINEWIDTH = 2.5
DEFAULT_TSNE_CVE_VULNERABLE_LINEWIDTH = 1.45
DEFAULT_TSNE_CVE_ZORDER_BOOST = 2.0
DEFAULT_TSNE_CLASS_COLORS = {
    0: '#3182bd',
    1: '#e6550d',
}
COHORT_STYLES = {
    'juliet_after_fine_tuned': {
        'cohort_label': 'Juliet / After Fine-tuned',
        'marker': 'o',
        'size': 80,
        'alpha': 0.22,
        'zorder': 1,
        'edgecolor': '#3182bd',
    },
    'cve_before_fine_tuned': {
        'cohort_label': 'CVE / Before Fine-tuned',
        'marker': '^',
        'size': 180,
        'alpha': 0.92,
        'zorder': 3,
        'edgecolor': '#111111',
    },
    'cve_after_fine_tuned': {
        'cohort_label': 'CVE / After Fine-tuned',
        'marker': 's',
        'size': 165,
        'alpha': 0.96,
        'zorder': 4,
        'edgecolor': '#111111',
    },
}


@dataclass(frozen=True)
class TripletCohortSpec:
    cohort_key: str
    feature_npz_path: Path
    source_csv_path: Path
    prediction_csv_path: Path | None = None
    prediction_kind: str | None = None

    @property
    def cohort_label(self) -> str:
        try:
            return str(COHORT_STYLES[self.cohort_key]['cohort_label'])
        except KeyError as exc:
            raise ValueError(f'Unsupported triplet cohort key: {self.cohort_key}') from exc


@dataclass(frozen=True)
class TripletTSNERequest:
    model_name: str
    plot_title: str
    output_dir: Path
    cohorts: Sequence[TripletCohortSpec]
    overwrite: bool = False


@dataclass(frozen=True)
class TripletTSNEResult:
    output_dir: Path
    image_path: Path
    cache_path: Path
    points_jsonl_path: Path


@dataclass(frozen=True)
class _LoadedCohort:
    spec: TripletCohortSpec
    features: np.ndarray
    labels: np.ndarray
    source_rows: list[tuple[int, dict[str, str]]]
    predictions: list[dict[str, Any] | None]


@dataclass(frozen=True)
class _ClassPairLink:
    cohort_key: str
    patched_index: int
    vulnerable_index: int
    pair_key: str


def build_triplet_artifact_paths(output_dir: Path) -> tuple[Path, Path, Path]:
    base_path = Path(output_dir) / TRIPLET_BASENAME
    return (
        Path(f'{base_path}.jpeg'),
        Path(f'{base_path}-tsne-features.json'),
        Path(f'{base_path}-points.jsonl'),
    )


def export_triplet_tsne(request: TripletTSNERequest) -> TripletTSNEResult:
    if len(request.cohorts) != 3:
        raise ValueError('Triplet t-SNE requires exactly 3 cohorts.')

    prepare_output_dir(request.output_dir, overwrite=request.overwrite)
    image_path, cache_path, points_jsonl_path = build_triplet_artifact_paths(request.output_dir)

    loaded_cohorts = [_load_cohort(spec) for spec in request.cohorts]
    feature_dims = {cohort.features.shape[1] for cohort in loaded_cohorts}
    if len(feature_dims) != 1:
        dim_summary = ', '.join(
            f'{cohort.spec.cohort_key}={cohort.features.shape}' for cohort in loaded_cohorts
        )
        raise ValueError(f'Triplet t-SNE feature dimensions must match: {dim_summary}')

    combined_features = np.concatenate(
        [cohort.features for cohort in loaded_cohorts],
        axis=0,
    )
    combined_labels = np.concatenate([cohort.labels for cohort in loaded_cohorts], axis=0)
    combined_cohort_keys = np.concatenate(
        [
            np.full(cohort.features.shape[0], cohort.spec.cohort_key, dtype=object)
            for cohort in loaded_cohorts
        ],
        axis=0,
    )

    embedding = _fit_embedding(combined_features)
    if embedding is None:
        raise ValueError(
            'Triplet t-SNE requires at least 2 total samples across the combined cohorts.'
        )

    point_rows = _build_point_rows(loaded_cohorts, embedding)
    cache_payload = {
        'title': request.plot_title,
        'model_name': request.model_name,
        'embedding': embedding.tolist(),
        'labels': combined_labels.astype(int).tolist(),
        'cohort_source': combined_cohort_keys.tolist(),
        'cohort_names': {spec.cohort_key: spec.cohort_label for spec in request.cohorts},
        'class_names': {str(key): value for key, value in TRIPLET_CLASS_NAMES.items()},
        'feature_paths': {spec.cohort_key: str(spec.feature_npz_path) for spec in request.cohorts},
        'source_csv_paths': {
            spec.cohort_key: str(spec.source_csv_path) for spec in request.cohorts
        },
        'points_jsonl': str(points_jsonl_path),
    }
    write_json(cache_path, cache_payload)
    write_jsonl(points_jsonl_path, point_rows)
    _plot_triplet_embedding(
        embedding,
        combined_labels,
        combined_cohort_keys,
        request=request,
        image_path=image_path,
        loaded_cohorts=loaded_cohorts,
    )
    return TripletTSNEResult(
        output_dir=request.output_dir,
        image_path=image_path,
        cache_path=cache_path,
        points_jsonl_path=points_jsonl_path,
    )


def _load_cohort(spec: TripletCohortSpec) -> _LoadedCohort:
    features, labels = _load_feature_artifact(spec.feature_npz_path)
    source_rows = _load_test_rows(spec.source_csv_path)
    if features.ndim != 2:
        raise ValueError(
            f'Triplet t-SNE expects 2D feature arrays: {spec.feature_npz_path} -> {features.shape}'
        )
    if labels.ndim != 1:
        labels = np.asarray(labels).reshape(-1)
    if features.shape[0] != labels.shape[0]:
        raise ValueError(
            'Triplet t-SNE feature/label count mismatch: '
            f'{spec.feature_npz_path} -> features={features.shape[0]}, labels={labels.shape[0]}'
        )
    if len(source_rows) != features.shape[0]:
        raise ValueError(
            'Triplet t-SNE CSV/feature sample count mismatch: '
            f'{spec.source_csv_path} -> test_rows={len(source_rows)}, '
            f'{spec.feature_npz_path} -> feature_rows={features.shape[0]}'
        )

    labels = np.asarray(labels, dtype=np.int64)
    expected_labels = np.asarray(
        [
            _parse_required_binary_label(row['target'], field_name='target')
            for _, row in source_rows
        ],
        dtype=np.int64,
    )
    if not np.array_equal(labels, expected_labels):
        raise ValueError(
            'Triplet t-SNE label order mismatch between feature export and source CSV: '
            f'{spec.feature_npz_path} vs {spec.source_csv_path}'
        )

    label_values = set(labels.tolist())
    if label_values != {0, 1}:
        raise ValueError(
            'Triplet t-SNE requires both Patched and Vulnerable samples in each cohort: '
            f'{spec.cohort_key} -> {sorted(label_values)}'
        )

    prediction_rows = _load_prediction_rows(
        spec.prediction_csv_path,
        prediction_kind=spec.prediction_kind,
        expected_count=features.shape[0],
    )
    if prediction_rows is None:
        prediction_rows = [None] * features.shape[0]

    for index, prediction_row in enumerate(prediction_rows):
        if prediction_row is None:
            continue
        reference_label = prediction_row.get('reference_label')
        if reference_label is not None and int(reference_label) != int(expected_labels[index]):
            raise ValueError(
                'Triplet t-SNE prediction/label mismatch: '
                f'{spec.prediction_csv_path} row {index} does not match {spec.source_csv_path}'
            )
        if (
            prediction_row.get('prediction') is not None
            and prediction_row.get('confusion_matrix') is None
        ):
            prediction_row['confusion_matrix'] = _confusion_label(
                int(expected_labels[index]),
                int(prediction_row['prediction']),
            )

    return _LoadedCohort(
        spec=spec,
        features=features,
        labels=labels,
        source_rows=source_rows,
        predictions=prediction_rows,
    )


def _load_feature_artifact(feature_npz_path: Path) -> tuple[np.ndarray, np.ndarray]:
    if not feature_npz_path.exists():
        raise FileNotFoundError(f'Triplet t-SNE feature NPZ not found: {feature_npz_path}')
    with np.load(feature_npz_path) as payload:
        return np.asarray(payload['features']), np.asarray(payload['labels'])


def _load_test_rows(source_csv_path: Path) -> list[tuple[int, dict[str, str]]]:
    if not source_csv_path.exists():
        raise FileNotFoundError(f'Triplet t-SNE source CSV not found: {source_csv_path}')

    csv.field_size_limit(sys.maxsize)
    with source_csv_path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        missing_columns = {'dataset_type', 'target'} - fieldnames
        if missing_columns:
            raise ValueError(
                'Triplet t-SNE source CSV missing required columns: '
                f'{", ".join(sorted(missing_columns))}: {source_csv_path}'
            )

        rows = [
            (row_index, dict(row))
            for row_index, row in enumerate(reader)
            if str(row.get('dataset_type') or '').strip() == 'test'
        ]

    if not rows:
        raise ValueError(f'Triplet t-SNE source CSV must contain test rows: {source_csv_path}')
    return rows


def _load_prediction_rows(
    prediction_csv_path: Path | None,
    *,
    prediction_kind: str | None,
    expected_count: int,
) -> list[dict[str, Any] | None] | None:
    if prediction_csv_path is None or prediction_kind is None:
        return None
    if not prediction_csv_path.exists():
        raise FileNotFoundError(f'Triplet t-SNE prediction CSV not found: {prediction_csv_path}')
    if prediction_kind == PDBERT_PREDICTION_KIND:
        return _load_pdbert_predictions(prediction_csv_path, expected_count=expected_count)
    if prediction_kind == LINEVUL_PREDICTION_KIND:
        return _load_linevul_predictions(prediction_csv_path, expected_count=expected_count)
    raise ValueError(f'Unsupported triplet t-SNE prediction kind: {prediction_kind}')


def _load_pdbert_predictions(
    prediction_csv_path: Path,
    *,
    expected_count: int,
) -> list[dict[str, Any] | None]:
    rows = _load_csv_rows(prediction_csv_path)
    if not rows:
        raise ValueError(f'Triplet t-SNE prediction CSV is empty: {prediction_csv_path}')

    if 'dataset_type' in rows[0]:
        filtered_rows = [
            row for row in rows if str(row.get('dataset_type') or '').strip() == 'test'
        ]
        if filtered_rows:
            rows = filtered_rows

    if len(rows) != expected_count:
        raise ValueError(
            'Triplet t-SNE PDBERT prediction count mismatch: '
            f'{prediction_csv_path} -> rows={len(rows)}, expected={expected_count}'
        )

    prediction_rows: list[dict[str, Any] | None] = []
    for row in rows:
        prediction = _parse_optional_binary_label(row.get('model_predict'))
        confusion = str(row.get('confusion_matrix') or '').strip() or None
        prediction_rows.append(
            {
                'prediction': prediction,
                'confusion_matrix': confusion,
                'reference_label': None,
            }
        )
    return prediction_rows


def _load_linevul_predictions(
    prediction_csv_path: Path,
    *,
    expected_count: int,
) -> list[dict[str, Any] | None]:
    rows = _load_csv_rows(prediction_csv_path)
    if len(rows) != expected_count:
        raise ValueError(
            'Triplet t-SNE LineVul prediction count mismatch: '
            f'{prediction_csv_path} -> rows={len(rows)}, expected={expected_count}'
        )

    prediction_rows: list[dict[str, Any] | None] = []
    for row in rows:
        reference_label = _parse_optional_binary_label(row.get('label'))
        prediction = _parse_optional_binary_label(row.get('pred'))
        confusion = (
            _confusion_label(reference_label, prediction)
            if reference_label is not None and prediction is not None
            else None
        )
        prediction_rows.append(
            {
                'prediction': prediction,
                'confusion_matrix': confusion,
                'reference_label': reference_label,
            }
        )
    return prediction_rows


def _load_csv_rows(path: Path) -> list[dict[str, str]]:
    csv.field_size_limit(sys.maxsize)
    with path.open('r', encoding='utf-8', newline='') as f:
        return [dict(row) for row in csv.DictReader(f)]


def _build_point_rows(
    loaded_cohorts: Sequence[_LoadedCohort],
    embedding: np.ndarray,
) -> list[dict[str, Any]]:
    point_rows: list[dict[str, Any]] = []
    global_index = 0
    for cohort in loaded_cohorts:
        for row_index, (source_csv_row_index, source_row) in enumerate(cohort.source_rows):
            prediction_row = cohort.predictions[row_index]
            point_rows.append(
                {
                    'point_index': global_index,
                    'x': float(embedding[global_index][0]),
                    'y': float(embedding[global_index][1]),
                    'cohort_key': cohort.spec.cohort_key,
                    'cohort_label': cohort.spec.cohort_label,
                    'class_value': int(cohort.labels[row_index]),
                    'class_label': TRIPLET_CLASS_NAMES[int(cohort.labels[row_index])],
                    'row_index': row_index,
                    'source_csv_row_index': source_csv_row_index,
                    'unique_id': str(source_row.get('unique_id') or ''),
                    'project': str(source_row.get('project') or ''),
                    'file_name': str(source_row.get('file_name') or ''),
                    'dataset_type': str(source_row.get('dataset_type') or ''),
                    'vulnerable_line_numbers': str(source_row.get('vulnerable_line_numbers') or ''),
                    'source_signature_path': str(source_row.get('source_signature_path') or ''),
                    'commit_hash': str(source_row.get('commit_hash') or ''),
                    'source_csv': str(cohort.spec.source_csv_path),
                    'source_feature_npz': str(cohort.spec.feature_npz_path),
                    'prediction': (
                        prediction_row.get('prediction') if prediction_row is not None else None
                    ),
                    'confusion_matrix': (
                        prediction_row.get('confusion_matrix')
                        if prediction_row is not None
                        else None
                    ),
                    'processed_func_excerpt': _excerpt(source_row.get('processed_func')),
                }
            )
            global_index += 1
    return point_rows


def _fit_embedding(features: np.ndarray) -> np.ndarray | None:
    if features.shape[0] < 2:
        return None

    perplexity = min(30, features.shape[0] - 1)
    embedded = _run_exact_tsne(
        features,
        perplexity=float(perplexity),
        random_state=0,
    )
    x_min, x_max = np.min(embedded, axis=0), np.max(embedded, axis=0)
    denom = np.where((x_max - x_min) == 0, 1, (x_max - x_min))
    return (embedded - x_min) / denom


def _run_exact_tsne(
    features: np.ndarray,
    *,
    perplexity: float,
    random_state: int,
    iterations: int = 750,
    initial_dims: int = 50,
    learning_rate: float = 200.0,
) -> np.ndarray:
    reduced = _pca_reduce(features, dims=min(initial_dims, features.shape[1]))
    n_samples = reduced.shape[0]
    pairwise_affinity = _binary_search_pairwise_affinity(
        reduced,
        perplexity=perplexity,
    )
    pairwise_affinity = pairwise_affinity + pairwise_affinity.T
    pairwise_affinity = np.maximum(pairwise_affinity / np.sum(pairwise_affinity), 1e-12)
    pairwise_affinity *= 4.0

    rng = np.random.default_rng(random_state)
    embedding = rng.normal(0.0, 1e-4, size=(n_samples, 2))
    embedding_update = np.zeros_like(embedding)
    gradient = np.zeros_like(embedding)
    gains = np.ones_like(embedding)

    for iteration in range(iterations):
        num = _student_t_kernel(embedding)
        q_distribution = np.maximum(num / np.sum(num), 1e-12)
        pairwise_delta = pairwise_affinity - q_distribution

        for row_index in range(n_samples):
            gradient[row_index] = np.sum(
                (pairwise_delta[:, row_index] * num[:, row_index])[:, np.newaxis]
                * (embedding[row_index] - embedding),
                axis=0,
            )
        gradient *= 4.0

        momentum = 0.5 if iteration < 250 else 0.8
        gains = np.where(
            (gradient > 0) != (embedding_update > 0),
            gains + 0.2,
            gains * 0.8,
        )
        gains = np.maximum(gains, 0.01)
        embedding_update = momentum * embedding_update - learning_rate * (gains * gradient)
        embedding += embedding_update
        embedding -= np.mean(embedding, axis=0)

        if iteration == 100:
            pairwise_affinity /= 4.0

    return embedding


def _pca_reduce(features: np.ndarray, *, dims: int) -> np.ndarray:
    centered = np.asarray(features, dtype=np.float64) - np.mean(features, axis=0)
    if dims <= 0 or centered.shape[1] <= dims:
        return centered
    _, _, vh = np.linalg.svd(centered, full_matrices=False)
    return centered @ vh[:dims].T


def _binary_search_pairwise_affinity(
    features: np.ndarray,
    *,
    perplexity: float,
    tol: float = 1e-5,
) -> np.ndarray:
    n_samples = features.shape[0]
    squared_norm = np.sum(np.square(features), axis=1)
    distances = (
        -2.0 * np.dot(features, features.T)
        + squared_norm[:, np.newaxis]
        + squared_norm[np.newaxis, :]
    )

    affinity = np.zeros((n_samples, n_samples), dtype=np.float64)
    log_perplexity = np.log(perplexity)

    for row_index in range(n_samples):
        beta = 1.0
        beta_min = -np.inf
        beta_max = np.inf
        mask = np.ones(n_samples, dtype=bool)
        mask[row_index] = False
        row_distances = distances[row_index, mask]
        entropy, row_affinity = _entropy_and_probabilities(row_distances, beta)
        entropy_diff = entropy - log_perplexity
        iteration = 0
        while abs(entropy_diff) > tol and iteration < 50:
            if entropy_diff > 0:
                beta_min = beta
                beta = beta * 2.0 if np.isinf(beta_max) else (beta + beta_max) / 2.0
            else:
                beta_max = beta
                beta = beta / 2.0 if np.isinf(beta_min) else (beta + beta_min) / 2.0

            entropy, row_affinity = _entropy_and_probabilities(row_distances, beta)
            entropy_diff = entropy - log_perplexity
            iteration += 1

        affinity[row_index, mask] = row_affinity

    return affinity


def _entropy_and_probabilities(distances: np.ndarray, beta: float) -> tuple[float, np.ndarray]:
    probabilities = np.exp(-distances * beta)
    probabilities_sum = np.sum(probabilities)
    if probabilities_sum <= 0.0:
        fallback = np.full(distances.shape[0], 1.0 / max(distances.shape[0], 1))
        return 0.0, fallback
    entropy = (
        np.log(probabilities_sum) + beta * np.sum(distances * probabilities) / probabilities_sum
    )
    probabilities = probabilities / probabilities_sum
    return float(entropy), probabilities


def _student_t_kernel(embedding: np.ndarray) -> np.ndarray:
    squared_norm = np.sum(np.square(embedding), axis=1)
    kernel = (
        -2.0 * np.dot(embedding, embedding.T)
        + squared_norm[:, np.newaxis]
        + squared_norm[np.newaxis, :]
    )
    kernel = 1.0 / (1.0 + kernel)
    np.fill_diagonal(kernel, 0.0)
    return kernel


def _plot_triplet_embedding(
    embedding: np.ndarray,
    labels: np.ndarray,
    cohort_source: np.ndarray,
    *,
    request: TripletTSNERequest,
    image_path: Path,
    loaded_cohorts: Sequence[_LoadedCohort],
) -> None:
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=DEFAULT_TSNE_FIGSIZE, edgecolor='black')
    group_specs = _build_group_specs(request.cohorts)
    rng = np.random.default_rng(DEFAULT_TSNE_SHUFFLE_SEED)
    _scatter_triplet_groups(
        ax,
        embedding,
        labels,
        cohort_source,
        group_specs,
        rng=rng,
    )

    ax.set_title(request.plot_title)
    ax.set_box_aspect(1)
    ax.set_xticks([])
    ax.set_yticks([])
    _add_triplet_legends(ax)
    fig.tight_layout(rect=(0, 0, 1, DEFAULT_TSNE_LAYOUT_TOP))
    fig.savefig(image_path, dpi=300)
    plt.close(fig)


def _add_triplet_legends(ax: Any) -> None:
    color_legend = ax.legend(
        handles=_build_class_legend_handles(),
        title='Color',
        frameon=False,
        loc='lower center',
        bbox_to_anchor=(0.5, DEFAULT_TSNE_COLOR_LEGEND_Y),
        ncol=2,
        fontsize=11,
        title_fontsize=11,
        borderaxespad=0.0,
        handletextpad=0.6,
        columnspacing=1.5,
    )
    ax.add_artist(color_legend)
    ax.legend(
        handles=_build_cohort_legend_handles(),
        title='Marker',
        frameon=False,
        loc='lower center',
        bbox_to_anchor=(0.5, DEFAULT_TSNE_MARKER_LEGEND_Y),
        ncol=3,
        fontsize=11,
        title_fontsize=11,
        borderaxespad=0.0,
        handletextpad=0.6,
        columnspacing=1.5,
    )


def _build_class_legend_handles() -> list[Any]:
    from matplotlib.lines import Line2D

    return [
        Line2D(
            [],
            [],
            linestyle='None',
            marker='o',
            markerfacecolor=DEFAULT_TSNE_CLASS_COLORS[0],
            markeredgecolor=DEFAULT_TSNE_CLASS_COLORS[0],
            markersize=9,
            label='Patched / Non-vulnerable',
        ),
        Line2D(
            [],
            [],
            linestyle='None',
            marker='o',
            markerfacecolor=DEFAULT_TSNE_CLASS_COLORS[1],
            markeredgecolor=DEFAULT_TSNE_CLASS_COLORS[1],
            markersize=9,
            label='Vulnerable',
        ),
    ]


def _build_cohort_legend_handles() -> list[Any]:
    from matplotlib.lines import Line2D

    return [
        Line2D(
            [],
            [],
            linestyle='None',
            marker='o',
            markerfacecolor='white',
            markeredgecolor='#111111',
            markeredgewidth=DEFAULT_TSNE_MARKER_LINEWIDTH,
            markersize=9,
            label='Juliet, fine-tuned',
        ),
        Line2D(
            [],
            [],
            linestyle='None',
            marker='^',
            markerfacecolor='white',
            markeredgecolor='#111111',
            markeredgewidth=DEFAULT_TSNE_MARKER_LINEWIDTH,
            markersize=10,
            label='CVE / Before Fine-tuned',
        ),
        Line2D(
            [],
            [],
            linestyle='None',
            marker='s',
            markerfacecolor='white',
            markeredgecolor='#111111',
            markeredgewidth=DEFAULT_TSNE_MARKER_LINEWIDTH,
            markersize=9,
            label='CVE / After Fine-tuned',
        ),
    ]


def _scatter_triplet_groups(
    ax: Any,
    embedding: np.ndarray,
    labels: np.ndarray,
    cohort_source: np.ndarray,
    group_specs: Sequence[dict[str, Any]],
    *,
    rng: np.random.Generator | None = None,
    add_legend: bool = False,
    cohort_keys: set[str] | None = None,
    size_scale: float = 1.0,
) -> None:
    for group_spec in group_specs:
        if cohort_keys is not None and group_spec['cohort_key'] not in cohort_keys:
            continue

        mask = (labels == group_spec['class_value']) & (cohort_source == group_spec['cohort_key'])
        point_indices = np.flatnonzero(mask)
        if point_indices.size == 0:
            continue

        scatter_size = float(group_spec['size']) * size_scale
        if add_legend:
            ax.scatter(
                [],
                [],
                marker=group_spec['marker'],
                facecolors=group_spec['facecolor'],
                edgecolors=group_spec['edgecolor'],
                s=scatter_size,
                alpha=group_spec['alpha'],
                linewidths=group_spec['linewidth'],
                label=group_spec['label'],
            )

        ordered_indices = rng.permutation(point_indices) if rng is not None else point_indices
        for point_index in ordered_indices:
            point = embedding[int(point_index)]
            ax.scatter(
                point[0],
                point[1],
                marker=group_spec['marker'],
                facecolors=group_spec['facecolor'],
                edgecolors=group_spec['edgecolor'],
                s=scatter_size,
                alpha=group_spec['alpha'],
                linewidths=group_spec['linewidth'],
                zorder=group_spec['zorder'],
                label='_nolegend_',
            )


def _plot_class_pair_links(
    ax: Any,
    embedding: np.ndarray,
    class_pair_links: Sequence[_ClassPairLink],
    *,
    label: str | None = None,
    linewidth: float = DEFAULT_TSNE_PAIR_LINK_LINEWIDTH,
    alpha: float = DEFAULT_TSNE_PAIR_LINK_ALPHA,
) -> None:
    wrote_label = False
    for pair_link in class_pair_links:
        patched_point = embedding[pair_link.patched_index]
        vulnerable_point = embedding[pair_link.vulnerable_index]
        link_label = label if label is not None and not wrote_label else '_nolegend_'
        ax.plot(
            [patched_point[0], vulnerable_point[0]],
            [patched_point[1], vulnerable_point[1]],
            color=DEFAULT_TSNE_PAIR_LINK_COLOR,
            alpha=alpha,
            linewidth=linewidth,
            zorder=2.5,
            solid_capstyle='round',
            label=link_label,
        )
        wrote_label = wrote_label or label is not None


def _is_cve_cohort_key(cohort_key: str) -> bool:
    return cohort_key.startswith('cve_')


def _build_group_specs(cohorts: Sequence[TripletCohortSpec]) -> list[dict[str, Any]]:
    group_specs: list[dict[str, Any]] = []
    for cohort in cohorts:
        style = COHORT_STYLES[cohort.cohort_key]
        for class_value in (0, 1):
            facecolor = DEFAULT_TSNE_CLASS_COLORS[int(class_value)]
            edgecolor = style['edgecolor']
            size = style['size']
            alpha = style['alpha']
            linewidth = DEFAULT_TSNE_MARKER_LINEWIDTH
            zorder = style['zorder']
            if _is_cve_cohort_key(cohort.cohort_key):
                if int(class_value) == 0:
                    facecolor = 'none'
                    edgecolor = DEFAULT_TSNE_CLASS_COLORS[0]
                    size = float(style['size']) * DEFAULT_TSNE_CVE_PATCHED_SIZE_SCALE
                    alpha = min(float(style['alpha']) + 0.03, 1.0)
                    linewidth = DEFAULT_TSNE_CVE_PATCHED_LINEWIDTH
                    zorder = float(style['zorder']) + DEFAULT_TSNE_CVE_ZORDER_BOOST + 0.3
                else:
                    facecolor = DEFAULT_TSNE_CLASS_COLORS[1]
                    edgecolor = '#111111'
                    size = float(style['size']) * DEFAULT_TSNE_CVE_VULNERABLE_SIZE_SCALE
                    alpha = min(float(style['alpha']) + 0.02, 1.0)
                    linewidth = DEFAULT_TSNE_CVE_VULNERABLE_LINEWIDTH
                    zorder = float(style['zorder']) + DEFAULT_TSNE_CVE_ZORDER_BOOST
            group_specs.append(
                {
                    'cohort_key': cohort.cohort_key,
                    'class_value': class_value,
                    'label': (f'{style["cohort_label"]} / {TRIPLET_CLASS_NAMES[int(class_value)]}'),
                    'marker': style['marker'],
                    'size': size,
                    'alpha': alpha,
                    'zorder': zorder,
                    'edgecolor': edgecolor,
                    'facecolor': facecolor,
                    'linewidth': linewidth,
                }
            )
    return group_specs


def _build_cve_class_pair_links(
    loaded_cohorts: Sequence[_LoadedCohort],
) -> list[_ClassPairLink]:
    class_pair_links: list[_ClassPairLink] = []
    global_offset = 0
    for cohort in loaded_cohorts:
        cohort_size = cohort.features.shape[0]
        if _is_cve_cohort_key(cohort.spec.cohort_key):
            class_pair_links.extend(
                _infer_cohort_class_pair_links(cohort, global_offset=global_offset)
            )
        global_offset += cohort_size
    return class_pair_links


def _infer_cohort_class_pair_links(
    cohort: _LoadedCohort,
    *,
    global_offset: int,
) -> list[_ClassPairLink]:
    entries: list[dict[str, Any]] = []
    for row_index, (source_csv_row_index, source_row) in enumerate(cohort.source_rows):
        entries.append(
            {
                'global_index': global_offset + row_index,
                'label': int(cohort.labels[row_index]),
                'source_csv_row_index': source_csv_row_index,
                'source_row': source_row,
            }
        )

    for field_name in ('pair_id', 'testcase_key', 'testcase_id', 'case_id'):
        grouped_links = _infer_grouped_class_pair_links(
            entries,
            cohort_key=cohort.spec.cohort_key,
            field_name=field_name,
        )
        if grouped_links:
            return grouped_links

    adjacent_links = _infer_adjacent_class_pair_links(
        entries,
        cohort_key=cohort.spec.cohort_key,
    )
    if adjacent_links:
        return adjacent_links

    return _infer_grouped_class_pair_links(
        entries,
        cohort_key=cohort.spec.cohort_key,
        field_name='project',
    )


def _infer_grouped_class_pair_links(
    entries: Sequence[dict[str, Any]],
    *,
    cohort_key: str,
    field_name: str,
) -> list[_ClassPairLink]:
    grouped_entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        pair_key = str(entry['source_row'].get(field_name) or '').strip()
        if pair_key:
            grouped_entries[pair_key].append(entry)

    class_pair_links: list[_ClassPairLink] = []
    for pair_key in sorted(grouped_entries):
        link = _class_pair_link_from_entries(
            grouped_entries[pair_key],
            cohort_key=cohort_key,
            pair_key=f'{field_name}:{pair_key}',
        )
        if link is not None:
            class_pair_links.append(link)
    return class_pair_links


def _infer_adjacent_class_pair_links(
    entries: Sequence[dict[str, Any]],
    *,
    cohort_key: str,
) -> list[_ClassPairLink]:
    if len(entries) < 2 or len(entries) % 2 != 0:
        return []

    class_pair_links: list[_ClassPairLink] = []
    ordered_entries = sorted(entries, key=lambda entry: int(entry['source_csv_row_index']))
    for offset in range(0, len(ordered_entries), 2):
        pair_entries = ordered_entries[offset : offset + 2]
        link = _class_pair_link_from_entries(
            pair_entries,
            cohort_key=cohort_key,
            pair_key=(
                'source_row_pair:'
                f'{pair_entries[0]["source_csv_row_index"]}-'
                f'{pair_entries[1]["source_csv_row_index"]}'
            ),
        )
        if link is None:
            return []
        class_pair_links.append(link)
    return class_pair_links


def _class_pair_link_from_entries(
    entries: Sequence[dict[str, Any]],
    *,
    cohort_key: str,
    pair_key: str,
) -> _ClassPairLink | None:
    patched_entries = [entry for entry in entries if int(entry['label']) == 0]
    vulnerable_entries = [entry for entry in entries if int(entry['label']) == 1]
    if len(patched_entries) != 1 or len(vulnerable_entries) != 1:
        return None
    return _ClassPairLink(
        cohort_key=cohort_key,
        patched_index=int(patched_entries[0]['global_index']),
        vulnerable_index=int(vulnerable_entries[0]['global_index']),
        pair_key=pair_key,
    )


def _parse_optional_binary_label(raw_value: Any) -> int | None:
    raw_text = str(raw_value or '').strip()
    if not raw_text:
        return None
    value = int(float(raw_text))
    if value not in {0, 1}:
        raise ValueError(f'Expected binary label, got: {raw_value}')
    return value


def _parse_required_binary_label(raw_value: Any, *, field_name: str) -> int:
    value = _parse_optional_binary_label(raw_value)
    if value is None:
        raise ValueError(f'Triplet t-SNE requires {field_name} to be 0 or 1, got: {raw_value}')
    return value


def _confusion_label(reference_label: int, prediction: int) -> str:
    if reference_label == 1 and prediction == 1:
        return 'TP'
    if reference_label == 0 and prediction == 0:
        return 'TN'
    if reference_label == 0 and prediction == 1:
        return 'FP'
    return 'FN'


def _excerpt(raw_text: Any, *, limit: int = 200) -> str:
    normalized = ' '.join(str(raw_text or '').split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + '...'


__all__ = [
    'LINEVUL_PREDICTION_KIND',
    'PDBERT_PREDICTION_KIND',
    'TRIPLET_BASENAME',
    'TRIPLET_CLASS_NAMES',
    'TripletCohortSpec',
    'TripletTSNERequest',
    'TripletTSNEResult',
    'build_triplet_artifact_paths',
    'export_triplet_tsne',
]
