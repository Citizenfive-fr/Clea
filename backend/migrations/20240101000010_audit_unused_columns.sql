-- Colonnes jamais remplies par le code : on ne garde pas de place pour des données
-- (adresse IP, détails libres) que le journal d'audit n'a pas besoin de conserver.
-- Les sauvegardes qui les contiennent encore se restaurent sans erreur : la restauration
-- ignore les colonnes qui n'existent plus.
ALTER TABLE audit_logs DROP COLUMN ip_address;
ALTER TABLE audit_logs DROP COLUMN metadata;
