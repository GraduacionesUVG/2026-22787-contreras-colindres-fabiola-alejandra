CREATE TABLE analisis (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    dominio VARCHAR(255),
    veredicto_final VARCHAR(20), -- SEGURO, MALICIOSO, INCIERTO, SOSPECHOSO
    filtro_decisivo VARCHAR(10), -- F1, F2.1, F2.2, F2.3
    criterios_f2_1 JSONB,
    score_heuristico NUMERIC(5,2), -- resultado de F2.1
    indicadores_f2_2 JSONB, -- resultados del sandbox (F2.2)
    screenshot_s3_key TEXT, -- URL firmada de S3 (F2.3)
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE reportes (
    id SERIAL PRIMARY KEY,
    analisis_id INTEGER REFERENCES analisis(id),
    url_reportada TEXT NOT NULL,
    motivo TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_analisis_dominio ON analisis(dominio);
CREATE INDEX idx_analisis_url ON analisis(url);