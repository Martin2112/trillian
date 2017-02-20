-- Creates the replication information to use the schema with CitusDB. Run the
-- storage.sql file first to create the tables.
--
-- Note: This is creating a 'per tenant' scheme where the data per tree is colocated.
-- This seems to be the only workable option but probably places scalability limits
-- on each tree.

-- These should be reference tables but it's not allowed for them to have foreign keys or
-- be a target for foreign keys so it doesn't work.
SELECT create_distributed_table('trees', 'treeid');
SELECT create_distributed_table('treecontrol', 'treeid', colocate with => 'trees');

-- Basic Tree Storage
SELECT create_distributed_table('subtree', 'treeid', colocate_with => 'trees');
SELECT create_distributed_table('treehead', 'treeid', colocate_with => 'trees');

-- Log Specific
SELECT create_distributed_table('leafdata', 'treeid', colocate_with => 'trees');
SELECT create_distributed_table('sequencedleafdata', 'treeid', colocate_with => 'trees');
SELECT create_distributed_table('unsequenced', 'treeid', colocate_with => 'trees');

-- Map Specific
SELECT create_distributed_table('mapleaf', 'treeid', colocate_with => 'trees');
SELECT create_distributed_table('maphead', 'treeid', colocate_with => 'trees');
