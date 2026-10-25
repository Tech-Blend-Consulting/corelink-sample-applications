-- Demo dataset for CoreLink dynamic database credentials.
--
-- Run with psql (it uses \c to switch databases):
--   PGSSLMODE=require psql -h <your-postgres-host> -U <admin-user> -d postgres \
--     -v ON_ERROR_STOP=1 -f database/corelink_demo.sql
--
-- Re-runnable: the demo database is dropped and recreated each time.
-- All data is fictitious (example.com addresses, card last-4 only).
--
-- CoreLink grants dynamic users rights on ALL TABLES IN SCHEMA public of the
-- connection's database, as of the moment the credential is minted. So every
-- table lives in public, and the data must exist before credentials are issued.

DROP DATABASE IF EXISTS corelink_demo WITH (FORCE);
CREATE DATABASE corelink_demo;

\c corelink_demo

SELECT setseed(0.42);

CREATE TABLE customers (
    id          serial PRIMARY KEY,
    full_name   text        NOT NULL,
    email       text        NOT NULL UNIQUE,
    country     text        NOT NULL,
    tier        text        NOT NULL CHECK (tier IN ('free', 'pro', 'enterprise')),
    created_at  timestamptz NOT NULL
);

CREATE TABLE products (
    id          serial PRIMARY KEY,
    sku         text           NOT NULL UNIQUE,
    name        text           NOT NULL,
    category    text           NOT NULL,
    unit_price  numeric(10, 2) NOT NULL,
    in_stock    integer        NOT NULL
);

CREATE TABLE orders (
    id           serial PRIMARY KEY,
    customer_id  integer     NOT NULL REFERENCES customers (id),
    status       text        NOT NULL CHECK (status IN ('pending', 'paid', 'shipped', 'refunded')),
    placed_at    timestamptz NOT NULL
);

CREATE TABLE order_items (
    order_id    integer        NOT NULL REFERENCES orders (id),
    product_id  integer        NOT NULL REFERENCES products (id),
    quantity    integer        NOT NULL,
    unit_price  numeric(10, 2) NOT NULL,
    PRIMARY KEY (order_id, product_id)
);

CREATE TABLE payments (
    id          serial PRIMARY KEY,
    order_id    integer        NOT NULL REFERENCES orders (id),
    amount      numeric(10, 2) NOT NULL,
    card_brand  text           NOT NULL,
    card_last4  char(4)        NOT NULL,
    paid_at     timestamptz    NOT NULL
);

-- The "sensitive" table: useful for showing that a read_only credential can see
-- it but not change it, and that the credential stops working when revoked.
CREATE TABLE employees (
    id          serial PRIMARY KEY,
    full_name   text           NOT NULL,
    email       text           NOT NULL UNIQUE,
    department  text           NOT NULL,
    title       text           NOT NULL,
    salary      numeric(10, 2) NOT NULL,
    hired_on    date           NOT NULL
);

-- Customers: 60 rows built from first/last name lists.
INSERT INTO customers (full_name, email, country, tier, created_at)
SELECT f || ' ' || l,
       lower(f || '.' || l || n) || '@example.com',
       (ARRAY['US', 'US', 'US', 'CA', 'GB', 'DE', 'AU', 'NL'])[1 + floor(random() * 8)::int],
       (ARRAY['free', 'free', 'pro', 'pro', 'enterprise'])[1 + floor(random() * 5)::int],
       now() - (random() * 720 || ' days')::interval
FROM (
    SELECT n,
           (ARRAY['Ava','Liam','Maya','Noah','Zoe','Ethan','Iris','Omar','Lena','Ravi',
                  'Chloe','Mateo','Priya','Jonas','Sofia'])[1 + (n % 15)] AS f,
           (ARRAY['Chen','Patel','Garcia','Okafor','Nguyen','Schmidt','Rossi','Kim'])[1 + (n % 8)] AS l
    FROM generate_series(1, 60) AS n
) s;

INSERT INTO products (sku, name, category, unit_price, in_stock) VALUES
    ('HW-1001', 'Edge Gateway Mini',        'hardware',     249.00,  120),
    ('HW-1002', 'Edge Gateway Pro',         'hardware',     649.00,   45),
    ('HW-1003', 'Hardware Security Key',    'hardware',      49.00,  800),
    ('HW-1004', 'Rack Mount Kit',           'hardware',      89.00,  210),
    ('SW-2001', 'Starter License (1 yr)',   'software',     199.00, 9999),
    ('SW-2002', 'Team License (1 yr)',      'software',     990.00, 9999),
    ('SW-2003', 'Enterprise License (1 yr)','software',    4990.00, 9999),
    ('SW-2004', 'Audit Add-on',             'software',     490.00, 9999),
    ('SV-3001', 'Onboarding Workshop',      'services',    1500.00,   20),
    ('SV-3002', 'Architecture Review',      'services',    3200.00,   10),
    ('SV-3003', 'Premium Support (1 yr)',   'services',    2400.00, 9999),
    ('AC-4001', 'USB-C Cable 2m',           'accessories',   12.00, 1500),
    ('AC-4002', 'Power Adapter',            'accessories',   29.00,  640),
    ('AC-4003', 'Field Carry Case',         'accessories',   59.00,  300);

-- Orders: 300 across the last year.
INSERT INTO orders (customer_id, status, placed_at)
SELECT 1 + floor(random() * 60)::int,
       (ARRAY['paid', 'paid', 'paid', 'shipped', 'shipped', 'pending', 'refunded'])[1 + floor(random() * 7)::int],
       now() - (random() * 365 || ' days')::interval
FROM generate_series(1, 300);

-- One to three distinct products per order.
INSERT INTO order_items (order_id, product_id, quantity, unit_price)
SELECT o.id, p.id, 1 + floor(random() * 4)::int, p.unit_price
FROM orders o
CROSS JOIN LATERAL (
    SELECT id, unit_price FROM products
    WHERE o.id > 0  -- correlate so each order gets its own random pick
    ORDER BY random()
    LIMIT 1 + floor(random() * 3)::int
) p;

-- A payment for every order that got past pending.
INSERT INTO payments (order_id, amount, card_brand, card_last4, paid_at)
SELECT o.id,
       t.total,
       (ARRAY['visa', 'mastercard', 'amex'])[1 + floor(random() * 3)::int],
       lpad(floor(random() * 10000)::int::text, 4, '0'),
       o.placed_at + interval '3 minutes'
FROM orders o
JOIN (SELECT order_id, sum(quantity * unit_price) AS total FROM order_items GROUP BY order_id) t
  ON t.order_id = o.id
WHERE o.status <> 'pending';

INSERT INTO employees (full_name, email, department, title, salary, hired_on) VALUES
    ('Dana Whitfield',  'dana.whitfield@example.com',  'Engineering', 'VP Engineering',        245000, '2019-03-11'),
    ('Marcus Bell',     'marcus.bell@example.com',     'Engineering', 'Staff Engineer',        212000, '2020-07-01'),
    ('Yuki Tanaka',     'yuki.tanaka@example.com',     'Engineering', 'Senior Engineer',       178000, '2021-02-15'),
    ('Felix Andersson', 'felix.andersson@example.com', 'Engineering', 'Engineer',              142000, '2023-09-05'),
    ('Amara Osei',      'amara.osei@example.com',      'Security',    'CISO',                  260000, '2018-11-20'),
    ('Hugo Martin',     'hugo.martin@example.com',     'Security',    'Security Engineer',     168000, '2022-04-18'),
    ('Grace Liu',       'grace.liu@example.com',       'Finance',     'Controller',            189000, '2020-01-06'),
    ('Samir Haddad',    'samir.haddad@example.com',    'Finance',     'Financial Analyst',     118000, '2024-03-25'),
    ('Elena Petrova',   'elena.petrova@example.com',   'Sales',       'Account Executive',     135000, '2022-10-10'),
    ('Tom Becker',      'tom.becker@example.com',      'Sales',       'Sales Engineer',        151000, '2023-01-30'),
    ('Nia Robinson',    'nia.robinson@example.com',    'Support',     'Support Lead',          112000, '2021-06-14'),
    ('Leo Moreau',      'leo.moreau@example.com',      'Support',     'Support Engineer',       96000, '2024-08-19');

-- A view a demo app can query in one line. Views are tables to GRANT ... ON ALL
-- TABLES, so dynamic credentials get it too.
CREATE VIEW revenue_by_month AS
SELECT date_trunc('month', p.paid_at)::date AS month,
       count(*)                             AS payments,
       sum(p.amount)                        AS revenue
FROM payments p
JOIN orders o ON o.id = p.order_id
WHERE o.status <> 'refunded'
GROUP BY 1
ORDER BY 1;

ANALYZE;

SELECT 'customers' AS table_name, count(*) AS rows FROM customers
UNION ALL SELECT 'products',    count(*) FROM products
UNION ALL SELECT 'orders',      count(*) FROM orders
UNION ALL SELECT 'order_items', count(*) FROM order_items
UNION ALL SELECT 'payments',    count(*) FROM payments
UNION ALL SELECT 'employees',   count(*) FROM employees;
