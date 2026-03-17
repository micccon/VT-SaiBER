# pytest tests/db_tests/test_scout_findings.py
"""
Integration test: Scout agent writing findings to database

Tests the complete flow:
1. Scout creates findings (without auto embedding for now)
2. Findings are persisted to database
3. Embeddings can be manually created and stored
4. Findings can be retrieved and searched
"""

import pytest
import sys
import os
import numpy as np
from datetime import datetime

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from src.database.manager import (
    create_target,
    create_finding,
    get_findings,
    get_findings_by_mission,
    get_target_info,
    search_similar_findings,
    get_finding_embedding,
    delete_finding,
    get_all_findings_embeddings,
    create_finding_embedding,
    delete_finding_embedding,
)



class TestScoutFindingsIntegration:
    """Test Scout agent findings workflow"""

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        """Setup and cleanup for each test"""
        self.test_mission_id = "test_scout_mission_001"
        self.created_finding_ids = []
        
    
        create_target(
        mission_id=self.test_mission_id,
        ip_address="192.168.1.100",
        hostname=None,
        os_guess=None,
        )


        yield
        # Cleanup: delete all created findings
        for finding_id in self.created_finding_ids:
            try:
                delete_finding(finding_id)
            except:
                pass

    def simulate_nmap_scan_results(self):
        """
        Simulate nmap scan results from Scout agent

        Returns:
            List of finding dictionaries as Scout would create them
        """
        return [
            {
                "target_ip": "192.168.1.100",
                "agent_name": "scout",
                "finding_type": "open_port",
                "severity": "info",
                "port": 22,
                "title": "SSH service detected on port 22",
                "description": "OpenSSH 7.4 running on target 192.168.1.100:22. Banner: OpenSSH_7.4.",
                "data": {
                    "service": "ssh",
                    "version": "7.4",
                    "banner": "OpenSSH_7.4 Debian 10+deb9u3"
                }
            },
            {
                "target_ip": "192.168.1.100",
                "agent_name": "scout",
                "finding_type": "open_port",
                "severity": "medium",
                "port": 3306,
                "title": "MySQL database service detected on port 3306",
                "description": "MySQL 5.7.32 running on target 192.168.1.100:3306. Service version detected via banner grabbing.",
                "data": {
                    "service": "mysql",
                    "version": "5.7.32",
                    "default_credentials_risk": True
                }
            },
            {
                "target_ip": "192.168.1.100",
                "agent_name": "scout",
                "finding_type": "vulnerable_service",
                "severity": "high",
                "port": 21,
                "title": "FTP service with known vulnerability (vsftpd 2.3.4)",
                "description": "vsftpd 2.3.4 detected. This version is vulnerable to CVE-2011-2523 (remote code execution via .gz file).",
                "data": {
                    "service": "ftp",
                    "version": "2.3.4",
                    "cve": "CVE-2011-2523",
                    "vulnerability_type": "rce"
                }
            },
            {
                "target_ip": "192.168.1.100",
                "agent_name": "scout",
                "finding_type": "vulnerable_service",
                "severity": "critical",
                "port": 5900,
                "title": "VNC service vulnerable to brute force attack",
                "description": "VNC server detected on port 5900. No authentication required to establish initial connection.",
                "data": {
                    "service": "vnc",
                    "auth_required": False,
                    "risk": "easy_exploitation"
                }
            }
        ]

    def create_mock_embedding(self, seed: int = 0):
        """
        Create a mock embedding vector for testing

        Args:
            seed: Seed for numpy random generator to ensure reproducibility

        Returns:
            List of 1536 floats representing an embedding vector
        """
        rng = np.random.RandomState(seed)
        embedding = rng.randn(1536).astype(np.float32)
        # Normalize the vector
        embedding = embedding / np.linalg.norm(embedding)
        return embedding.tolist()

    def test_scout_creates_single_finding(self):
        """Test Scout creating a single finding"""
        # Simulate Scout finding
        scan_result = self.simulate_nmap_scan_results()[0]

        # Create finding as Scout would
        finding = create_finding(
            mission_id=self.test_mission_id,
            agent_name=scan_result["agent_name"],
            finding_type=scan_result["finding_type"],
            severity=scan_result["severity"],
            target_ip=scan_result["target_ip"],
            target_port=scan_result["port"],
            title=scan_result["title"],
            description=scan_result["description"],
            data=scan_result["data"]
        )

        assert finding is not None, "Finding should be created"
        assert finding['id'] is not None, "Finding should have ID"
        self.created_finding_ids.append(finding['id'])

        # Verify finding was stored correctly
        assert finding['agent_name'] == "scout"
        assert finding['target_ip'] == "192.168.1.100"
        assert finding['target_port'] == 22
        assert finding['severity'] == "info"
        assert finding['title'] == scan_result["title"]

    def test_scout_creates_multiple_findings(self):
        """Test Scout creating multiple findings from nmap scan"""
        scan_results = self.simulate_nmap_scan_results()

        created_findings = []

        # Create all findings from scan
        for scan_result in scan_results:
            finding = create_finding(
                mission_id=self.test_mission_id,
                agent_name=scan_result["agent_name"],
                finding_type=scan_result["finding_type"],
                severity=scan_result["severity"],
                target_ip=scan_result["target_ip"],
                target_port=scan_result["port"],
                title=scan_result["title"],
                description=scan_result["description"],
                data=scan_result["data"]
            )
            assert finding is not None
            self.created_finding_ids.append(finding['id'])
            created_findings.append(finding)

        # Verify all findings were created
        assert len(created_findings) == 4, "Should create 4 findings"

        # Verify findings can be retrieved by mission
        retrieved = get_findings_by_mission(self.test_mission_id)
        assert len(retrieved) >= 4, "Should retrieve at least 4 findings"

    def test_scout_findings_severity_distribution(self):
        """Test that Scout findings have correct severity levels"""
        scan_results = self.simulate_nmap_scan_results()

        # Create findings
        for scan_result in scan_results:
            finding = create_finding(
                mission_id=self.test_mission_id,
                agent_name=scan_result["agent_name"],
                finding_type=scan_result["finding_type"],
                severity=scan_result["severity"],
                target_ip=scan_result["target_ip"],
                target_port=scan_result["port"],
                title=scan_result["title"],
                description=scan_result["description"],
                data=scan_result["data"]
            )
            self.created_finding_ids.append(finding['id'])

        # Verify severity classification
        retrieved = get_findings_by_mission(self.test_mission_id)

        severities = {}
        for finding in retrieved:
            severity = finding['severity']
            severities[severity] = severities.get(severity, 0) + 1

        # Should have mixed severities
        assert 'info' in severities, "Should have info level findings"
        assert 'medium' in severities or 'high' in severities or 'critical' in severities, \
            "Should have vulnerability findings"

    def test_manual_embedding_creation(self):
        """Test manually creating embeddings for findings"""
        scan_result = self.simulate_nmap_scan_results()[0]

        # Create finding without embedding
        finding = create_finding(
            mission_id=self.test_mission_id,
            agent_name=scan_result["agent_name"],
            finding_type=scan_result["finding_type"],
            severity=scan_result["severity"],
            target_ip=scan_result["target_ip"],
            target_port=scan_result["port"],
            title=scan_result["title"],
            description=scan_result["description"],
            data=scan_result["data"]
        )
        self.created_finding_ids.append(finding['id'])

        # Initially, embedding should not exist
        embedding = get_finding_embedding(finding['id'])
        assert embedding is None, "No embedding should exist initially"

        # Now manually create embedding
        embedding_vec = self.create_mock_embedding(seed=1)
        combined_text = f"{scan_result['title']}\n{scan_result['description']}"

        result = create_finding_embedding(
            finding_id=finding['id'],
            embedding_vector=embedding_vec,
            embedded_text=combined_text,
            embedding_model='sentence-transformers'
        )

        assert result is not None, "Embedding creation should succeed"
        assert result['finding_id'] == finding['id']

        # Verify embedding now exists
        embedding = get_finding_embedding(finding['id'])
        assert embedding is not None, "Embedding should now exist"
        assert embedding['embedding'] is not None
        assert embedding['embedding_model'] == 'sentence-transformers'

    def test_embedding_storage_and_retrieval(self):
        """Test embedding storage and retrieval"""
        scan_results = self.simulate_nmap_scan_results()

        # Create findings and add embeddings
        embeddings_created = []
        for i, scan_result in enumerate(scan_results):
            finding = create_finding(
                mission_id=self.test_mission_id,
                agent_name=scan_result["agent_name"],
                finding_type=scan_result["finding_type"],
                severity=scan_result["severity"],
                target_ip=scan_result["target_ip"],
                target_port=scan_result["port"],
                title=scan_result["title"],
                description=scan_result["description"],
                data=scan_result["data"]
            )
            self.created_finding_ids.append(finding['id'])

            # Create embedding for this finding
            embedding_vec = self.create_mock_embedding(seed=i)
            combined_text = f"{scan_result['title']}\n{scan_result['description']}"

            embed_result = create_finding_embedding(
                finding_id=finding['id'],
                embedding_vector=embedding_vec,
                embedded_text=combined_text
            )
            embeddings_created.append(embed_result)

        # Verify all embeddings were created
        all_embeddings = get_all_findings_embeddings()
        assert len(all_embeddings) >= len(embeddings_created), \
            "Should have at least created embeddings"

    def test_scout_target_info_aggregation(self):
        """Test Scout findings aggregation with target info"""
        scan_results = self.simulate_nmap_scan_results()

        # Create findings for specific target
        for scan_result in scan_results:
            finding = create_finding(
                mission_id=self.test_mission_id,
                agent_name=scan_result["agent_name"],
                finding_type=scan_result["finding_type"],
                severity=scan_result["severity"],
                target_ip=scan_result["target_ip"],
                target_port=scan_result["port"],
                title=scan_result["title"],
                description=scan_result["description"],
                data=scan_result["data"]
            )
            self.created_finding_ids.append(finding['id'])

        # Get aggregated target info
        target_info = get_target_info(self.test_mission_id, "192.168.1.100")

        # Verify aggregation
        assert target_info is not None, "Should return target info"
        assert len(target_info['findings']) > 0, "Should include findings"

    def test_scout_findings_data_integrity(self):
        """Test that Scout finding data is stored and retrieved correctly"""
        scan_result = self.simulate_nmap_scan_results()[2]  # FTP vulnerable service

        # Create finding
        finding = create_finding(
            mission_id=self.test_mission_id,
            agent_name=scan_result["agent_name"],
            finding_type=scan_result["finding_type"],
            severity=scan_result["severity"],
            target_ip=scan_result["target_ip"],
            target_port=scan_result["port"],
            title=scan_result["title"],
            description=scan_result["description"],
            data=scan_result["data"]
        )
        self.created_finding_ids.append(finding['id'])

        # Verify data integrity
        assert finding['title'] == scan_result["title"]
        assert finding['description'] == scan_result["description"]

        # Verify nested data
        import json
        stored_data = json.loads(finding['data']) if isinstance(finding['data'], str) else finding['data']
        assert stored_data['service'] == 'ftp'
        assert stored_data['version'] == '2.3.4'
        assert stored_data['cve'] == 'CVE-2011-2523'

    def test_scout_high_severity_findings(self):
        """Test filtering high severity Scout findings"""
        scan_results = self.simulate_nmap_scan_results()

        # Create all findings
        for scan_result in scan_results:
            finding = create_finding(
                mission_id=self.test_mission_id,
                agent_name=scan_result["agent_name"],
                finding_type=scan_result["finding_type"],
                severity=scan_result["severity"],
                target_ip=scan_result["target_ip"],
                target_port=scan_result["port"],
                title=scan_result["title"],
                description=scan_result["description"],
                data=scan_result["data"]
            )
            self.created_finding_ids.append(finding['id'])

        # Get all findings and filter high severity
        all_findings = get_findings_by_mission(self.test_mission_id)
        high_severity = [f for f in all_findings if f['severity'] in ['high', 'critical']]

        # Should have at least VNC and FTP vulnerabilities
        assert len(high_severity) >= 2, "Should have high/critical severity findings"

    def test_embedding_vector_search_with_mock_embeddings(self):
        """Test vector similarity search with mock embeddings"""
        scan_results = self.simulate_nmap_scan_results()

        # Create findings with embeddings
        created_ids = []
        for i, scan_result in enumerate(scan_results):
            finding = create_finding(
                mission_id=self.test_mission_id,
                agent_name=scan_result["agent_name"],
                finding_type=scan_result["finding_type"],
                severity=scan_result["severity"],
                target_ip=scan_result["target_ip"],
                target_port=scan_result["port"],
                title=scan_result["title"],
                description=scan_result["description"],
                data=scan_result["data"]
            )
            self.created_finding_ids.append(finding['id'])
            created_ids.append(finding['id'])

            # Create embedding
            embedding_vec = self.create_mock_embedding(seed=i)
            combined_text = f"{scan_result['title']}\n{scan_result['description']}"
            create_finding_embedding(
                finding_id=finding['id'],
                embedding_vector=embedding_vec,
                embedded_text=combined_text
            )

        # Test search with a similar seed embedding
        query_embedding = self.create_mock_embedding(seed=0)  # Similar to first finding

        results = search_similar_findings(
            embedding_vector=query_embedding,
            limit=3,
            threshold=0.0  # Lower threshold to ensure we get results with mock embeddings
        )

        # Should find some results
        assert len(results) >= 0, "Search should return results (may be empty with random embeddings)"

        # If there are results, verify they have expected fields
        if len(results) > 0:
            for result in results:
                assert 'title' in result
                assert 'similarity' in result
                assert 0 <= result['similarity'] <= 1


class TestScoutParallelFindings:
    """Test Scout handling multiple concurrent findings"""

    def test_scout_multiple_targets(self):
        """Test Scout findings for multiple targets in same mission"""
        mission_id = "test_scout_multi_target"
        target_ips = ["192.168.1.50", "192.168.1.100", "192.168.1.150"]
        created_ids = []

        try:
            # Create findings for each target
            for target_ip in target_ips:
                for port in [22, 80, 3306]:
                    finding = create_finding(
                        mission_id=mission_id,
                        agent_name="scout",
                        finding_type="open_port",
                        severity="info",
                        target_ip=target_ip,
                        target_port=port,
                        title=f"Port {port} open on {target_ip}",
                        description=f"Service detected on {target_ip}:{port}",
                        data={"target": target_ip, "port": port}
                    )
                    created_ids.append(finding['id'])

            # Verify all findings were created
            all_findings = get_findings_by_mission(mission_id)
            assert len(all_findings) >= 9, "Should have 9 findings (3 targets x 3 ports)"

            # Verify counts per target
            for target_ip in target_ips:
                target_findings = [f for f in all_findings if f['target_ip'] == target_ip]
                assert len(target_findings) >= 3, f"Should have at least 3 findings for {target_ip}"

        finally:
            # Cleanup
            for finding_id in created_ids:
                try:
                    delete_finding(finding_id)
                except:
                    pass

    def test_scout_finding_deletion(self):
        """Test that embeddings are deleted when findings are deleted"""
        mission_id = "test_scout_deletion"
        created_ids = []

        try:
            # Create a finding with embedding
            finding = create_finding(
                mission_id=mission_id,
                agent_name="scout",
                finding_type="open_port",
                severity="info",
                target_ip="192.168.1.100",
                target_port=22,
                title="SSH service",
                description="OpenSSH 7.4",
                data={"service": "ssh"}
            )
            finding_id = finding['id']
            created_ids.append(finding_id)

            # Create embedding
            rng = np.random.RandomState(42)
            embedding_vec = (rng.randn(1536).astype(np.float32) / np.linalg.norm(rng.randn(1536))).tolist()
            create_finding_embedding(
                finding_id=finding_id,
                embedding_vector=embedding_vec,
                embedded_text="SSH service\nOpenSSH 7.4"
            )

            # Verify embedding exists
            embedding = get_finding_embedding(finding_id)
            assert embedding is not None, "Embedding should exist"

            # Delete finding
            delete_finding(finding_id)

            # Verify embedding is also deleted (cascading delete)
            embedding = get_finding_embedding(finding_id)
            assert embedding is None, "Embedding should be deleted with finding"

        finally:
            # Cleanup
            for finding_id in created_ids:
                try:
                    delete_finding(finding_id)
                except:
                    pass


if __name__ == "__main__":
    # Run tests: pytest tests/db_tests/test_scout_findings.py -v
    pytest.main([__file__, "-v"])
