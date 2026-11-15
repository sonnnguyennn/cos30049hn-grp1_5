export type TrafficLabel = "benign" | "malicious";

export type Analysis = {
    schema_version: "traffic_analysis_v2";
    model: string;
    threshold: number;
    runtime: { numpy: string; xgboost: string };
    summary: {
        rows: number;
        features: number;
        benign: number;
        malicious: number;
        file_name: string | null;
        input_format: "csv" | "json" | null;
        file_size_bytes: number | null;
        mode: "manual_analysis";
        started_at: string;
        completed_at: string;
        processing_ms: number;
        inference_ms: number;
        malicious_rate: number;
        mean_score: number;
        mean_confidence: number;
        score_type: "probability_malicious";
        threshold: number;
        model: {
            id: string;
            name: string;
            algorithm: string;
            objective: string;
            sha256: string;
        };
        preprocessor: {
            name: string;
            feature_count: number;
            input_dtype: string;
            model_dtype: string;
            scaling_applied: boolean;
            steps: string[];
        };
        ground_truth: {
            source: "upload_metadata" | null;
            provided_rows: number;
            missing_rows: number;
            correct: number;
            incorrect: number;
            accuracy: number | null;
        };
    };
    results: {
        row: number;
        sample_name: string;
        label: TrafficLabel;
        score: number;
        probability_malicious: number;
        probability_benign: number;
        confidence: number;
        ground_truth: TrafficLabel | null;
        correct: boolean | null;
    }[];
    feature_stats: { feature: string; min: number; max: number; mean: number }[];
};
