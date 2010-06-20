ATTACH DATABASE "jabrss_res.db" AS res;

BEGIN;

DELETE FROM res.resource WHERE NOT EXISTS (SELECT 1 FROM user_resource WHERE user_resource.rid = resource.rid);

COMMIT;
