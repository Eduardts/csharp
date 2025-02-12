# R Implementation for Security Analytics

# Load required libraries
library(tidyverse)
library(caret)
library(xgboost)
library(anomalize)
library(tidylog)

# Threat Prediction Model
create_threat_model <- function(historical_data) {
    # Data preprocessing
    processed_data <- historical_data %>%
        mutate(
            timestamp = as.POSIXct(timestamp),
            attack_type = as.factor(attack_type)
        ) %>%
        select(-c(id, raw_log))
    
    # Feature engineering
    features <- processed_data %>%
        group_by(source_ip) %>%
        summarise(
            request_count = n(),
            error_rate = mean(status_code >= 400),
            avg_bytes = mean(bytes_sent),
            unique_paths = n_distinct(path)
        )
    
    # Split data
    set.seed(42)
    training_idx <- createDataPartition(features$attack_type, p = 0.8, list = FALSE)
    train_data <- features[training_idx, ]
    test_data <- features[-training_idx, ]
    
    # Train XGBoost model
    xgb_model <- train(
        x = train_data %>% select(-attack_type),
        y = train_data$attack_type,
        method = "xgbTree",
        trControl = trainControl(
            method = "cv",
            number = 5,
            verboseIter = TRUE
        )
    )
    
    return(list(
        model = xgb_model,
        features = features,
        metrics = evaluate_model(xgb_model, test_data)
    ))
}

# Access Log Analysis
analyze_access_logs <- function(logs, threshold = 0.95) {
    # Process logs
    processed_logs <- logs %>%
        mutate(
            timestamp = as.POSIXct(timestamp),
            hour = hour(timestamp)
        )
    
    # Detect anomalies
    anomalies <- processed_logs %>%
        group_by(user_id, hour) %>%
        summarise(
            access_count = n(),
            unique_resources = n_distinct(resource_id),
            failed_attempts = sum(status == "FAILED")
        ) %>%
        anomalize(
            method = "iqr",
            alpha = threshold
        )
    
    # Pattern analysis
    patterns <- processed_logs %>%
        group_by(user_id) %>%
        summarise(
            typical_hours = list(sort(unique(hour))),
            common_resources = list(names(sort(table(resource_id), decreasing = TRUE)[1:5])),
            failure_rate = mean(status == "FAILED")
        )
    
    return(list(
        anomalies = anomalies,
        patterns = patterns,
        risk_scores = calculate_risk_scores(anomalies, patterns)
    ))
}

# Risk Scoring
calculate_risk_scores <- function(anomalies, patterns) {
    risk_scores <- anomalies %>%
        left_join(patterns, by = "user_id") %>%
        mutate(
            risk_score = (
                anomaly_score * 0.4 +
                failure_rate * 0.3 +
                unique_resources_score * 0.3
            )
        ) %>%
        arrange(desc(risk_score))
    
    return(risk_scores)
}

# Model Evaluation
evaluate_model <- function(model, test_data) {
    predictions <- predict(model, newdata = test_data %>% select(-attack_type))
    
    # Calculate metrics
    confusion_matrix <- confusionMatrix(predictions, test_data$attack_type)
    roc_curve <- roc(test_data$attack_type, as.numeric(predictions))
    
    return(list(
        confusion_matrix = confusion_matrix,
        auc = auc(roc_curve),
        precision = precision(confusion_matrix),
        recall = recall(confusion_matrix)
    ))
}

