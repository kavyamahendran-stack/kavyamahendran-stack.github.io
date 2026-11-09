-- =====================================================================
-- Card Fraud Pattern Analysis
-- Author: Kavya Mahendran
-- Data:   881,441 simulated card transactions, 1 Jan to 31 Dec 2025,
--         999 customers, generated with the open-source Sparkov
--         simulator (the tool behind the well-known Kaggle
--         "Credit Card Transactions Fraud Detection" dataset).
-- Engine: SQLite 3.45
-- Goal:   Find the patterns that separate fraud from genuine spending,
--         then test simple detection rules a fraud team could use.
-- =====================================================================


-- ---------------------------------------------------------------------
-- STEP 0. Data quality checks (always do this before any analysis)
-- ---------------------------------------------------------------------

-- 0a. Size, date range and fraud count
SELECT COUNT(*)                  AS total_transactions,
       COUNT(DISTINCT customer_id) AS customers,
       MIN(trans_date)           AS first_date,
       MAX(trans_date)           AS last_date,
       SUM(is_fraud)             AS fraud_transactions
FROM transactions;

-- 0b. Missing values in key columns (expect 0 everywhere)
SELECT SUM(amount IS NULL)    AS missing_amount,
       SUM(category IS NULL)  AS missing_category,
       SUM(trans_time IS NULL) AS missing_time,
       SUM(is_fraud IS NULL)  AS missing_label
FROM transactions;

-- 0c. Duplicate IDs. The raw generator re-used 117,209 transaction IDs
--     across different transactions, so I replaced them with a new
--     unique ID (T0000001 ...). This check proves the fix worked.
SELECT COUNT(*) - COUNT(DISTINCT trans_id) AS duplicate_ids
FROM transactions;


-- ---------------------------------------------------------------------
-- STEP 1. Build a customers table so customer details live in one place
--         (later queries JOIN to it)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS customers;
CREATE TABLE customers AS
SELECT DISTINCT customer_id, gender, state, city_pop, dob
FROM transactions;


-- ---------------------------------------------------------------------
-- STEP 2. Headline KPIs
-- ---------------------------------------------------------------------
SELECT COUNT(*)                                     AS transactions,
       SUM(is_fraud)                                AS fraud_cases,
       ROUND(100.0 * AVG(is_fraud), 2)              AS fraud_rate_pct,
       ROUND(SUM(amount), 0)                        AS total_value,
       ROUND(SUM(CASE WHEN is_fraud = 1 THEN amount END), 0) AS fraud_value,
       ROUND(100.0 * SUM(CASE WHEN is_fraud = 1 THEN amount END)
             / SUM(amount), 1)                      AS fraud_share_of_value_pct,
       ROUND(AVG(CASE WHEN is_fraud = 1 THEN amount END), 2) AS avg_fraud_amount,
       ROUND(AVG(CASE WHEN is_fraud = 0 THEN amount END), 2) AS avg_genuine_amount
FROM transactions;


-- ---------------------------------------------------------------------
-- STEP 3. Fraud by merchant category
-- ---------------------------------------------------------------------
SELECT category,
       COUNT(*)                         AS transactions,
       SUM(is_fraud)                    AS fraud_cases,
       ROUND(100.0 * AVG(is_fraud), 2)  AS fraud_rate_pct,
       ROUND(SUM(CASE WHEN is_fraud = 1 THEN amount ELSE 0 END), 0) AS fraud_value
FROM transactions
GROUP BY category
ORDER BY fraud_rate_pct DESC;


-- ---------------------------------------------------------------------
-- STEP 4. Fraud by hour of day
-- ---------------------------------------------------------------------
SELECT CAST(SUBSTR(trans_time, 1, 2) AS INTEGER) AS hour,
       COUNT(*)                        AS transactions,
       SUM(is_fraud)                   AS fraud_cases,
       ROUND(100.0 * AVG(is_fraud), 2) AS fraud_rate_pct
FROM transactions
GROUP BY hour
ORDER BY hour;


-- ---------------------------------------------------------------------
-- STEP 5. Fraud by transaction amount band (CASE WHEN builds the bands)
-- ---------------------------------------------------------------------
SELECT CASE
         WHEN amount < 50   THEN '1. Under $50'
         WHEN amount < 200  THEN '2. $50 to $199'
         WHEN amount < 500  THEN '3. $200 to $499'
         WHEN amount < 1000 THEN '4. $500 to $999'
         ELSE                    '5. $1,000+'
       END                             AS amount_band,
       COUNT(*)                        AS transactions,
       SUM(is_fraud)                   AS fraud_cases,
       ROUND(100.0 * AVG(is_fraud), 2) AS fraud_rate_pct
FROM transactions
GROUP BY amount_band
ORDER BY amount_band;


-- ---------------------------------------------------------------------
-- STEP 6. Fraud by customer age (JOIN to the customers table)
-- ---------------------------------------------------------------------
SELECT CASE
         WHEN age < 25 THEN '18-24'
         WHEN age < 35 THEN '25-34'
         WHEN age < 50 THEN '35-49'
         WHEN age < 65 THEN '50-64'
         ELSE               '65+'
       END                             AS age_band,
       COUNT(*)                        AS transactions,
       SUM(is_fraud)                   AS fraud_cases,
       ROUND(100.0 * AVG(is_fraud), 2) AS fraud_rate_pct
FROM (
  SELECT t.is_fraud,
         (JULIANDAY(t.trans_date) - JULIANDAY(c.dob)) / 365.25 AS age
  FROM transactions t
  JOIN customers c ON c.customer_id = t.customer_id
)
GROUP BY age_band
ORDER BY age_band;


-- ---------------------------------------------------------------------
-- STEP 7. Monthly trend
-- ---------------------------------------------------------------------
SELECT SUBSTR(trans_date, 1, 7)        AS month,
       COUNT(*)                        AS transactions,
       SUM(is_fraud)                   AS fraud_cases,
       ROUND(100.0 * AVG(is_fraud), 2) AS fraud_rate_pct
FROM transactions
GROUP BY month
ORDER BY month;


-- ---------------------------------------------------------------------
-- STEP 8. Velocity: time since the same customer's previous transaction
--         LAG() is a window function: it looks back one row within each
--         customer's own history, ordered by time.
-- ---------------------------------------------------------------------
WITH gaps AS (
  SELECT is_fraud,
         (unix_time - LAG(unix_time) OVER (PARTITION BY customer_id
                                           ORDER BY unix_time)) / 60.0
           AS minutes_since_last
  FROM transactions
)
SELECT CASE
         WHEN minutes_since_last IS NULL THEN '0. First transaction'
         WHEN minutes_since_last < 10    THEN '1. Under 10 min'
         WHEN minutes_since_last < 60    THEN '2. 10 to 59 min'
         WHEN minutes_since_last < 360   THEN '3. 1 to 6 hours'
         WHEN minutes_since_last < 1440  THEN '4. 6 to 24 hours'
         ELSE                                 '5. Over 1 day'
       END                             AS gap_band,
       COUNT(*)                        AS transactions,
       SUM(is_fraud)                   AS fraud_cases,
       ROUND(100.0 * AVG(is_fraud), 2) AS fraud_rate_pct
FROM gaps
GROUP BY gap_band
ORDER BY gap_band;


-- ---------------------------------------------------------------------
-- STEP 9. Fraud bursts: how fraud behaves once a card is compromised
-- ---------------------------------------------------------------------
SELECT COUNT(*)                 AS customers_affected,
       ROUND(AVG(fraud_txns), 1) AS avg_fraud_txns_per_customer,
       ROUND(AVG(span_days), 1)  AS avg_days_from_first_to_last_fraud,
       MAX(fraud_txns)          AS max_fraud_txns
FROM (
  SELECT customer_id,
         COUNT(*) AS fraud_txns,
         JULIANDAY(MAX(trans_date)) - JULIANDAY(MIN(trans_date)) AS span_days
  FROM transactions
  WHERE is_fraud = 1
  GROUP BY customer_id
);


-- ---------------------------------------------------------------------
-- STEP 10. Distance check: does merchant distance separate fraud?
--          (It does not here, so I left it out of the rules.)
-- ---------------------------------------------------------------------
SELECT is_fraud,
       ROUND(AVG(distance_km), 1) AS avg_distance_km
FROM transactions
GROUP BY is_fraud;


-- ---------------------------------------------------------------------
-- STEP 11. Test detection rules
--   precision = of the alerts raised, how many were really fraud
--   recall    = of all fraud, how much the rule caught
-- ---------------------------------------------------------------------
WITH flagged AS (
  SELECT is_fraud, amount,
    CASE WHEN amount >= 200 THEN 1 ELSE 0 END AS r1_high_amount,
    CASE WHEN CAST(SUBSTR(trans_time, 1, 2) AS INTEGER) IN (22, 23, 0, 1, 2, 3)
         THEN 1 ELSE 0 END AS r2_night,
    CASE WHEN category IN ('shopping_net', 'misc_net', 'grocery_pos')
         THEN 1 ELSE 0 END AS r3_risky_category
  FROM transactions
),
rules AS (
  SELECT 'R1 Amount >= $200' AS rule, is_fraud, amount, r1_high_amount AS hit FROM flagged
  UNION ALL
  SELECT 'R2 Night (22:00-03:59)', is_fraud, amount, r2_night FROM flagged
  UNION ALL
  SELECT 'R3 High-risk category', is_fraud, amount, r3_risky_category FROM flagged
  UNION ALL
  SELECT 'R4 Amount >= $200 AND night', is_fraud, amount,
         r1_high_amount * r2_night FROM flagged
  UNION ALL
  SELECT 'R5 Amount >= $200 AND high-risk category', is_fraud, amount,
         r1_high_amount * r3_risky_category FROM flagged
)
SELECT rule,
       SUM(hit)                                         AS alerts,
       SUM(hit * is_fraud)                              AS fraud_caught,
       ROUND(100.0 * SUM(hit * is_fraud) / SUM(hit), 1) AS precision_pct,
       ROUND(100.0 * SUM(hit * is_fraud) / SUM(is_fraud), 1) AS recall_pct,
       ROUND(100.0 * SUM(hit * is_fraud * amount)
             / SUM(is_fraud * amount), 1)               AS fraud_value_caught_pct,
       ROUND(SUM(hit) / 365.0, 0)                       AS alerts_per_day
FROM rules
GROUP BY rule
ORDER BY rule;
