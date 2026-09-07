CREATE TABLE stackpilot.agent_inventory (
    agent_id uuid PRIMARY KEY REFERENCES stackpilot.agents(id) ON DELETE CASCADE,
    hostname text NOT NULL,
    os_id text NOT NULL,
    os_name text NOT NULL,
    os_version text NOT NULL,
    kernel_release text NOT NULL,
    architecture text NOT NULL,
    cpu_logical_cores integer NOT NULL,
    memory_total_bytes bigint NOT NULL,
    reported_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_inventory_hostname_check CHECK (length(hostname) >= 1 AND length(hostname) <= 255),
    CONSTRAINT agent_inventory_os_id_check CHECK (length(os_id) >= 1 AND length(os_id) <= 64),
    CONSTRAINT agent_inventory_os_name_check CHECK (length(os_name) >= 1 AND length(os_name) <= 128),
    CONSTRAINT agent_inventory_os_version_check CHECK (length(os_version) <= 128),
    CONSTRAINT agent_inventory_kernel_release_check CHECK (length(kernel_release) >= 1 AND length(kernel_release) <= 128),
    CONSTRAINT agent_inventory_architecture_check CHECK (length(architecture) >= 1 AND length(architecture) <= 32),
    CONSTRAINT agent_inventory_cpu_logical_cores_check CHECK (cpu_logical_cores > 0 AND cpu_logical_cores <= 1048576),
    CONSTRAINT agent_inventory_memory_total_bytes_check CHECK (memory_total_bytes > 0)
);
---- create above / drop below ----
DROP TABLE stackpilot.agent_inventory;
