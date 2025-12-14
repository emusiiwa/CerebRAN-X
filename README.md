# CerebRAN-X: A Dynamic Behavioural Dataset for Ransomware Detection

Abstract: Ransomware remains a critical threat, yet existing detection datasets suffer from severe class imbalance and limited family diversity. This study introduces CerebRAN-X, a dynamic behavioral dataset designed to address these limitations. We analysed 2,415 samples, comprising a near-balanced distribution of 1,167 ransomware variants across 45 families and 1,248 benign applications. Using a Cuckoo Sandbox environment, we extracted 5,110 behavioral indicators, including API calls and file operations. To validate the dataset, we implemented a machine learning pipeline using Random Forest and Logistic Regression. The Random Forest model achieved superior performance with 98.9% accuracy and a recall of 0.9957, missing only a single ransomware sample in the unseen test set. These results confirm that CerebRAN-X provides a high-quality, balanced benchmark for developing robust ransomware detection tools.

# Dataset Description

The CerebRAN dataset is a balanced collection of behavioural indicators designed for training and evaluating machine learning-based ransomware detectors. The dataset was created by performing dynamic analysis on 2,415 unique software samples in a Cuckoo Sandbox environment running a Windows 7 guest.

The dataset comprises:

1,167 ransomware samples, representing a diverse range of modern families (labelled as 1).

1,248 goodware samples, consisting of legitimate and benign software (labelled as 0).

Dynamic analysis generated an initial set of 1,356,584 unique behavioural features, including API calls, file system operations, registry modifications, and network activity. After a rigorous preprocessing phase to remove non-informative and zero-variance features, the final dataset used for modeling contains 5,110 distinct, predictive behavioural indicators. The features are one-hot encoded, with a value of '1' indicating the presence of a specific behaviour during execution and '0' indicating its absence.




<img width="2402" height="2990" alt="Family Distribution" src="https://github.com/user-attachments/assets/f9702364-105b-4358-8b2b-5f6467250d0d" />


# Disclaimer!

All ransomware analyses were conducted in controlled sandbox environments. This repository does not distribute raw binaries. However, we provide the hashes of the samples and complete metadata to help in downloading the samples. Researchers are advised to follow appropriate safety protocols when working with malware and to comply with their institution’s ethical and legal standards.
