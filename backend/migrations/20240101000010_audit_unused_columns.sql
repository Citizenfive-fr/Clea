-- Colonnes jamais remplies par le code : on ne garde pas de place pour des données
-- (adresse IP, détails libres) que le journal d'audit n'a pas besoin de conserver.
-- Une sauvegarde faite avant cette migration se restaure avec la version qui l'a
-- faite ; la mise à jour applique ensuite cette migration.
ALTER TABLE audit_logs DROP COLUMN ip_address;
ALTER TABLE audit_logs DROP COLUMN metadata;
