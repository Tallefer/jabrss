ATTACH DATABASE "jabrss_res.db" AS res;
SELECT jid, url FROM user NATURAL INNER JOIN user_resource NATURAL INNER JOIN res.resource ORDER BY jid, url;
