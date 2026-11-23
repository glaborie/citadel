-- Databases for services that share the Citadel Postgres instance.
-- POSTGRES_DB (citadel) is created by the image itself.
-- Temporal creates its own databases via auto-setup.

CREATE DATABASE keycloak;
CREATE DATABASE openfga;
