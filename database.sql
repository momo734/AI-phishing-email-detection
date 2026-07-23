CREATE DATABASE IF NOT EXISTS phishing_detector;
USE phishing_detector;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  email_content TEXT NOT NULL,
  model_used ENUM('logistic_regression', 'naive_bayes') NOT NULL,
  logistic_regression_score INT DEFAULT NULL,
  naive_bayes_score INT DEFAULT NULL,
  result VARCHAR(30) NOT NULL,
  tfidf_terms JSON NULL,
  scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
