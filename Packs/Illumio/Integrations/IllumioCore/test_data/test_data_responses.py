from illumio import VirtualService, Reference, ServicePort, TrafficFlow, TrafficNode, Workload, TimestampRange

VIRTUAL_SERVICE_SUCCESS = VirtualService(
    href='/orgs/1/sec_policy/draft/virtual_services/2a3fa5e7-68ce-482d-98a6-529166781a84',
    name='dummy-service', description=None, external_data_set=None,
    external_data_reference=None,
    caps=['write', 'provision', 'delete'], created_at='2022-08-30T10:16:59.412Z',
    updated_at='2022-08-30T10:16:59.415Z', deleted_at=None, update_type='create',
    delete_type=None,
    created_by=Reference(href='/users/68'), updated_by=Reference(href='/users/68'),
    deleted_by=None,
    apply_to='host_only', pce_fqdn=None, service=None, service_ports=[
        ServicePort(port=8443, proto=6, to_port=None, icmp_type=None, icmp_code=None, service_name=None,
                    process_name=None, windows_service_name=None, user_name=None)], service_addresses=[],
    ip_overrides=[], labels=[])

VIRTUAL_SERVICE_SUCCESS_UDP = VirtualService(
    href='/orgs/1/sec_policy/draft/virtual_services/e2914e54-a08e-4d77-bffc-f3f1f0dade88', name='dummy-service-UDP',
    description=None, external_data_set=None, external_data_reference=None, caps=['write', 'provision', 'delete'],
    created_at='2022-08-30T10:52:15.212Z', updated_at='2022-08-30T10:52:15.216Z', deleted_at=None, update_type='create',
    delete_type=None, created_by=Reference(href='/users/68'), updated_by=Reference(href='/users/68'), deleted_by=None,
    apply_to='host_only', pce_fqdn=None, service=None, service_ports=[
        ServicePort(port=3000, proto=17, to_port=None, icmp_type=None, icmp_code=None, service_name=None,
                    process_name=None, windows_service_name=None, user_name=None)], service_addresses=[],
    ip_overrides=[], labels=[])

TRAFFIC_ANALYSIS_RESPONSE = response = [
    TrafficFlow(src=TrafficNode(ip='0.0.0.0', label=None, workload=None, ip_lists=None, virtual_server=None,
                                virtual_service=None), dst=TrafficNode(ip='0.0.0.0', label=None, workload=Workload(
        href='/orgs/1/workloads/1f28c4e8-64ec-48b9-aa25-27611b7210f6', name='crest-snow-workload-1', description=None,
        external_data_set=None, external_data_reference=None, caps=None, created_at=None, updated_at=None,
        deleted_at=None,
        update_type=None, delete_type=None, created_by=None, updated_by=None, deleted_by=None,
        hostname='crest-snow-workload-1', os_type='linux', service_principal_name=None,
        agent_to_pce_certificate_authentication_id=None, distinguished_name=None, public_ip=None, interfaces=None,
        service_provider=None, data_center=None, data_center_zone=None, os_id=None, os_detail=None, online=None,
        deleted=None, ignored_interface_names=None, firewall_coexistence=None, containers_inherit_host_policy=None,
        blocked_connection_action=None, labels=[Reference(href='/orgs/1/labels/27357')], services=None,
        vulnerabilities_summary=None, detected_vulnerabilities=None, agent=None, ven=None, enforcement_mode=None,
        visibility_level=None, num_enforcement_boundaries=None, selectively_enforced_services=None,
        container_cluster=None,
        ike_authentication_certificate=None), ip_lists=None, virtual_server=None, virtual_service=None),
                service=ServicePort(port=8443, proto=6, to_port=None, icmp_type=None, icmp_code=None, service_name=None,
                                    process_name=None, windows_service_name=None, user_name=None), num_connections=1,
                state='closed', timestamp_range=TimestampRange(first_detected='2022-07-17T22:35:29Z',
                                                               last_detected='2022-07-17T22:35:29Z'), dst_bi=0,
                dst_bo=0,
                policy_decision='potentially_blocked', flow_direction='inbound', transmission=None, icmp_type=None,
                icmp_code=None, network=None), TrafficFlow(
        src=TrafficNode(ip='0.0.0.0', label=None, workload=None, ip_lists=None, virtual_server=None,
                        virtual_service=None), dst=TrafficNode(ip='0.0.0.0', label=None, workload=Workload(
            href='/orgs/1/workloads/a1a2bd2f-b74b-4068-a177-11b0cb1c92c4', name='crest-snow-workload-2',
            description=None,
            external_data_set=None, external_data_reference=None, caps=None, created_at=None, updated_at=None,
            deleted_at=None, update_type=None, delete_type=None, created_by=None, updated_by=None, deleted_by=None,
            hostname='crest-snow-workload-2', os_type='linux', service_principal_name=None,
            agent_to_pce_certificate_authentication_id=None, distinguished_name=None, public_ip=None, interfaces=None,
            service_provider=None, data_center=None, data_center_zone=None, os_id=None, os_detail=None, online=None,
            deleted=None, ignored_interface_names=None, firewall_coexistence=None, containers_inherit_host_policy=None,
            blocked_connection_action=None,
            labels=[Reference(href='/orgs/1/labels/3089'), Reference(href='/orgs/1/labels/10'),
                    Reference(href='/orgs/1/labels/27148'), Reference(href='/orgs/1/labels/27153')], services=None,
            vulnerabilities_summary=None, detected_vulnerabilities=None, agent=None, ven=None, enforcement_mode=None,
            visibility_level=None, num_enforcement_boundaries=None, selectively_enforced_services=None,
            container_cluster=None, ike_authentication_certificate=None), ip_lists=None, virtual_server=None,
                                                               virtual_service=None),
        service=ServicePort(port=8443, proto=6, to_port=None, icmp_type=None, icmp_code=None, service_name=None,
                            process_name=None, windows_service_name=None, user_name=None), num_connections=1,
        state='closed',
        timestamp_range=TimestampRange(first_detected='2022-07-18T11:24:33Z', last_detected='2022-07-18T11:24:33Z'),
        dst_bi=0, dst_bo=0, policy_decision='potentially_blocked', flow_direction='inbound', transmission=None,
        icmp_type=None, icmp_code=None, network=None)]
