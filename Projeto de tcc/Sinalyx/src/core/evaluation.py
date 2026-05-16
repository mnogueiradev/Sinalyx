"""
Funcoes de avaliacao e particionamento de dados do Sinalyx.

Este modulo concentra o que e compartilhado entre treino e validacao:
- split estruturado
- balanceamento opcional
- metricas binarias
- serializacao de relatorios
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split


def split_train_validation_test(
    X: pd.DataFrame,
    y: pd.Series,
    *,
    test_size: float = 0.15,
    validation_size: float = 0.15,
    random_state: int = 42,
) -> dict[str, pd.DataFrame | pd.Series]:
    """
    Separa um dataset em treino, validação e teste com estratificação.
    """
    if y is None:
        raise ValueError("O split estruturado exige rótulos disponíveis.")

    if not 0 < test_size < 1:
        raise ValueError("test_size deve estar entre 0 e 1.")

    if not 0 < validation_size < 1:
        raise ValueError("validation_size deve estar entre 0 e 1.")

    if test_size + validation_size >= 1:
        raise ValueError("A soma de test_size e validation_size deve ser menor que 1.")

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=test_size + validation_size,
        random_state=random_state,
        stratify=y,
    )

    validation_fraction = validation_size / (test_size + validation_size)
    X_validation, X_test, y_validation, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=1 - validation_fraction,
        random_state=random_state,
        stratify=y_temp,
    )

    return {
        "X_train": X_train.reset_index(drop=True),
        "y_train": y_train.reset_index(drop=True),
        "X_validation": X_validation.reset_index(drop=True),
        "y_validation": y_validation.reset_index(drop=True),
        "X_test": X_test.reset_index(drop=True),
        "y_test": y_test.reset_index(drop=True),
    }


def apply_balance_strategy(
    X: pd.DataFrame,
    y: pd.Series,
    strategy: str = "none",
    *,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Aplica balanceamento apenas ao conjunto de treino.
    """
    strategy_key = strategy.strip().lower()
    if strategy_key == "none":
        return X.reset_index(drop=True), y.reset_index(drop=True)

    frame = X.copy()
    frame["target"] = y.values

    class_counts = frame["target"].value_counts()
    if set(class_counts.index) != {0, 1}:
        return X.reset_index(drop=True), y.reset_index(drop=True)

    majority_label = int(class_counts.idxmax())
    minority_label = int(class_counts.idxmin())

    majority_frame = frame[frame["target"] == majority_label]
    minority_frame = frame[frame["target"] == minority_label]

    if strategy_key == "undersample_normal":
        sampled_majority = majority_frame.sample(
            n=len(minority_frame),
            random_state=random_state,
            replace=False,
        )
        balanced = pd.concat([sampled_majority, minority_frame], ignore_index=True)
    elif strategy_key == "oversample_attack":
        target_minority_size = min(len(majority_frame), len(minority_frame) * 2)
        sampled_minority = minority_frame.sample(
            n=target_minority_size,
            random_state=random_state,
            replace=True,
        )
        balanced = pd.concat([majority_frame, sampled_minority], ignore_index=True)
    else:
        raise ValueError(
            "Estratégia de balanceamento inválida. "
            "Use 'none', 'undersample_normal' ou 'oversample_attack'."
        )

    balanced = balanced.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    y_balanced = balanced.pop("target").astype(int)
    return balanced, y_balanced


def compute_binary_metrics(y_true, y_pred) -> dict:
    """
    Calcula métricas binárias e matriz de confusão em formato serializável.
    """
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="binary",
        zero_division=0,
    )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    total = tn + fp + fn + tp
    accuracy = (tp + tn) / total if total else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    selection_score = (
        (recall * 0.55)
        + (f1 * 0.25)
        + (precision * 0.10)
        + (specificity * 0.10)
    )

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "accuracy": float(accuracy),
        "specificity": float(specificity),
        "false_positive_rate": float(false_positive_rate),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "selection_score": float(selection_score),
    }


def candidate_ranking_key(result: dict) -> tuple[float, float, float, float]:
    """
    Define a ordenação de candidatos priorizando recall.
    """
    metrics = result["metrics"]
    return (
        float(metrics["recall"]),
        float(metrics["f1_score"]),
        -float(metrics["false_positive_rate"]),
        float(metrics["precision"]),
    )


def select_best_result(results: list[dict]) -> dict:
    """
    Seleciona o melhor candidato de uma lista de resultados avaliados.
    """
    if not results:
        raise ValueError("Nenhum resultado disponível para seleção.")
    return max(results, key=candidate_ranking_key)


def summarize_target_distribution(y: pd.Series) -> dict:
    """
    Resume a distribuição das classes em um dataset.
    """
    counts = y.astype(int).value_counts().to_dict()
    return {
        "normal": int(counts.get(0, 0)),
        "attack": int(counts.get(1, 0)),
        "total": int(len(y)),
    }


def save_json_report(path: str | Path, payload: dict) -> None:
    """
    Salva um relatório JSON em UTF-8.
    """
    target_path = Path(path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)
