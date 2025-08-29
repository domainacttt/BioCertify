// CertificateRegistry.test.ts
import { describe, expect, it, vi, beforeEach } from "vitest";

// Interfaces for type safety
interface ClarityResponse<T> {
  ok: boolean;
  value: T | number; // number for error codes
}

interface Certificate {
  hash: Uint8Array; // buff 32
  producer: string;
  volume: number;
  biofuelType: string;
  ghgReduction: number;
  productionDate: number;
  location: string;
  metadata: string;
  owner: string;
  retired: boolean;
  retirementReason: string | null;
  timestamp: number;
}

interface Verifier {
  active: boolean;
  addedBy: string;
  addedAt: number;
}

interface ComplianceLog {
  verifier: string;
  status: boolean;
  notes: string;
  timestamp: number;
}

interface Collaborator {
  role: string;
  permissions: string[];
  addedAt: number;
}

interface Version {
  updatedHash: Uint8Array;
  changes: string;
  timestamp: number;
}

interface License {
  expiry: number;
  terms: string;
  active: boolean;
}

interface ContractState {
  paused: boolean;
  admin: string;
  certificateCounter: number;
  certificates: Map<number, Certificate>;
  hashToId: Map<string, { certificateId: number }>; // Use string for hash key (hex representation)
  verifiers: Map<string, Verifier>;
  complianceLogs: Map<string, ComplianceLog>; // Key as `${certId}-${logId}`
  collaborators: Map<string, Collaborator>; // Key as `${certId}-${collaborator}`
  versions: Map<string, Version>; // Key as `${certId}-${version}`
  licenses: Map<string, License>; // Key as `${certId}-${licensee}`
}

// Mock contract implementation
class CertificateRegistryMock {
  private state: ContractState = {
    paused: false,
    admin: "deployer",
    certificateCounter: 0,
    certificates: new Map(),
    hashToId: new Map(),
    verifiers: new Map(),
    complianceLogs: new Map(),
    collaborators: new Map(),
    versions: new Map(),
    licenses: new Map(),
  };

  private ERR_DUPLICATE_HASH = 1;
  private ERR_UNAUTHORIZED = 2;
  private ERR_INVALID_AMOUNT = 3;
  private ERR_NOT_FOUND = 4;
  private ERR_ALREADY_RETIRED = 5;
  private ERR_INVALID_METADATA = 6;
  private ERR_PAUSED = 7;
  private ERR_INVALID_VERIFIER = 8;
  private ERR_COMPLIANCE_FAIL = 9;
  private MAX_METADATA_LEN = 500;
  private MIN_GHG_REDUCTION = 20;

  private mockBlockHeight = 1000; // Mock block height

  // Helper to simulate buff 32 as Uint8Array, but use hex string for maps
  private buffToHex(buff: Uint8Array): string {
    return Array.from(buff).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private incrementBlockHeight() {
    this.mockBlockHeight += 1;
  }

  pauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = true;
    return { ok: true, value: true };
  }

  unpauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.paused = false;
    return { ok: true, value: true };
  }

  setAdmin(caller: string, newAdmin: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.admin = newAdmin;
    return { ok: true, value: true };
  }

  addVerifier(caller: string, verifier: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.verifiers.set(verifier, { active: true, addedBy: caller, addedAt: this.mockBlockHeight });
    return { ok: true, value: true };
  }

  removeVerifier(caller: string, verifier: string): ClarityResponse<boolean> {
    if (caller !== this.state.admin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const existing = this.state.verifiers.get(verifier);
    if (existing) {
      this.state.verifiers.set(verifier, { ...existing, active: false });
      return { ok: true, value: true };
    }
    return { ok: false, value: this.ERR_NOT_FOUND };
  }

  issueCertificate(
    caller: string,
    hash: Uint8Array,
    volume: number,
    biofuelType: string,
    ghgReduction: number,
    location: string,
    metadata: string
  ): ClarityResponse<number> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const hashHex = this.buffToHex(hash);
    if (this.state.hashToId.has(hashHex)) {
      return { ok: false, value: this.ERR_DUPLICATE_HASH };
    }
    if (volume <= 0) {
      return { ok: false, value: this.ERR_INVALID_AMOUNT };
    }
    if (ghgReduction < this.MIN_GHG_REDUCTION) {
      return { ok: false, value: this.ERR_COMPLIANCE_FAIL };
    }
    if (metadata.length > this.MAX_METADATA_LEN) {
      return { ok: false, value: this.ERR_INVALID_METADATA };
    }
    const certId = ++this.state.certificateCounter;
    const timestamp = this.mockBlockHeight;
    this.state.certificates.set(certId, {
      hash,
      producer: caller,
      volume,
      biofuelType,
      ghgReduction,
      productionDate: timestamp,
      location,
      metadata,
      owner: caller,
      retired: false,
      retirementReason: null,
      timestamp,
    });
    this.state.hashToId.set(hashHex, { certificateId: certId });
    this.incrementBlockHeight();
    return { ok: true, value: certId };
  }

  transferCertificate(caller: string, certId: number, newOwner: string): ClarityResponse<boolean> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const cert = this.state.certificates.get(certId);
    if (!cert) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cert.owner !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (cert.retired) {
      return { ok: false, value: this.ERR_ALREADY_RETIRED };
    }
    this.state.certificates.set(certId, { ...cert, owner: newOwner });
    return { ok: true, value: true };
  }

  retireCertificate(caller: string, certId: number, reason: string): ClarityResponse<boolean> {
    if (this.state.paused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const cert = this.state.certificates.get(certId);
    if (!cert) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cert.owner !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (cert.retired) {
      return { ok: false, value: this.ERR_ALREADY_RETIRED };
    }
    this.state.certificates.set(certId, { ...cert, retired: true, retirementReason: reason });
    return { ok: true, value: true };
  }

  addCollaborator(caller: string, certId: number, collaborator: string, role: string, permissions: string[]): ClarityResponse<boolean> {
    const cert = this.state.certificates.get(certId);
    if (!cert) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cert.owner !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${certId}-${collaborator}`;
    this.state.collaborators.set(key, { role, permissions, addedAt: this.mockBlockHeight });
    return { ok: true, value: true };
  }

  logCompliance(caller: string, certId: number, status: boolean, notes: string, logId: number): ClarityResponse<boolean> {
    const cert = this.state.certificates.get(certId);
    if (!cert) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    const verifier = this.state.verifiers.get(caller);
    if (!verifier || !verifier.active) {
      return { ok: false, value: this.ERR_INVALID_VERIFIER };
    }
    const key = `${certId}-${logId}`;
    this.state.complianceLogs.set(key, { verifier: caller, status, notes, timestamp: this.mockBlockHeight });
    return { ok: true, value: true };
  }

  registerVersion(caller: string, certId: number, version: number, newHash: Uint8Array, changes: string): ClarityResponse<boolean> {
    const cert = this.state.certificates.get(certId);
    if (!cert) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cert.owner !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${certId}-${version}`;
    this.state.versions.set(key, { updatedHash: newHash, changes, timestamp: this.mockBlockHeight });
    return { ok: true, value: true };
  }

  grantLicense(caller: string, certId: number, licensee: string, duration: number, terms: string): ClarityResponse<boolean> {
    const cert = this.state.certificates.get(certId);
    if (!cert) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cert.owner !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${certId}-${licensee}`;
    this.state.licenses.set(key, { expiry: this.mockBlockHeight + duration, terms, active: true });
    return { ok: true, value: true };
  }

  getCertificateDetails(certId: number): ClarityResponse<Certificate | null> {
    return { ok: true, value: this.state.certificates.get(certId) ?? null };
  }

  getCertificateByHash(hash: Uint8Array): ClarityResponse<Certificate | null> {
    const hashHex = this.buffToHex(hash);
    const idOpt = this.state.hashToId.get(hashHex);
    if (!idOpt) {
      return { ok: true, value: null };
    }
    return this.getCertificateDetails(idOpt.certificateId);
  }

  verifyOwnership(certId: number, owner: string): ClarityResponse<boolean> {
    const cert = this.state.certificates.get(certId);
    if (!cert) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    return { ok: true, value: cert.owner === owner };
  }

  isContractPaused(): ClarityResponse<boolean> {
    return { ok: true, value: this.state.paused };
  }

  getAdmin(): ClarityResponse<string> {
    return { ok: true, value: this.state.admin };
  }

  getVerifierStatus(verifier: string): ClarityResponse<Verifier | null> {
    return { ok: true, value: this.state.verifiers.get(verifier) ?? null };
  }

  getComplianceLog(certId: number, logId: number): ClarityResponse<ComplianceLog | null> {
    const key = `${certId}-${logId}`;
    return { ok: true, value: this.state.complianceLogs.get(key) ?? null };
  }

  getCollaborator(certId: number, collaborator: string): ClarityResponse<Collaborator | null> {
    const key = `${certId}-${collaborator}`;
    return { ok: true, value: this.state.collaborators.get(key) ?? null };
  }

  getVersion(certId: number, version: number): ClarityResponse<Version | null> {
    const key = `${certId}-${version}`;
    return { ok: true, value: this.state.versions.get(key) ?? null };
  }

  getLicense(certId: number, licensee: string): ClarityResponse<License | null> {
    const key = `${certId}-${licensee}`;
    return { ok: true, value: this.state.licenses.get(key) ?? null };
  }
}

// Test setup
const accounts = {
  deployer: "deployer",
  producer: "wallet_1",
  user1: "wallet_2",
  verifier: "wallet_3",
};

const mockHash = new Uint8Array(32).fill(1); // Sample buff 32
const mockNewHash = new Uint8Array(32).fill(2);

describe("CertificateRegistry Contract", () => {
  let contract: CertificateRegistryMock;

  beforeEach(() => {
    contract = new CertificateRegistryMock();
    vi.resetAllMocks();
  });

  it("should allow admin to pause and unpause contract", () => {
    const pauseResult = contract.pauseContract(accounts.deployer);
    expect(pauseResult).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: true });

    const issueDuringPause = contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test metadata"
    );
    expect(issueDuringPause).toEqual({ ok: false, value: 7 });

    const unpauseResult = contract.unpauseContract(accounts.deployer);
    expect(unpauseResult).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: false });
  });

  it("should allow admin to add and remove verifier", () => {
    const addVerifier = contract.addVerifier(accounts.deployer, accounts.verifier);
    expect(addVerifier).toEqual({ ok: true, value: true });
    const status = contract.getVerifierStatus(accounts.verifier);
    expect(status).toEqual({
      ok: true,
      value: expect.objectContaining({ active: true }),
    });

    const removeVerifier = contract.removeVerifier(accounts.deployer, accounts.verifier);
    expect(removeVerifier).toEqual({ ok: true, value: true });
    const updatedStatus = contract.getVerifierStatus(accounts.verifier);
    expect(updatedStatus).toEqual({
      ok: true,
      value: expect.objectContaining({ active: false }),
    });
  });

  it("should issue a new certificate successfully", () => {
    const issueResult = contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test metadata"
    );
    expect(issueResult).toEqual({ ok: true, value: 1 });

    const details = contract.getCertificateDetails(1);
    expect(details).toEqual({
      ok: true,
      value: expect.objectContaining({
        volume: 1000,
        biofuelType: "Biodiesel",
        ghgReduction: 80,
        owner: accounts.producer,
        retired: false,
      }),
    });

    const byHash = contract.getCertificateByHash(mockHash);
    expect(byHash).toEqual(details);
  });

  it("should prevent duplicate hash issuance", () => {
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test metadata"
    );

    const duplicate = contract.issueCertificate(
      accounts.producer,
      mockHash,
      2000,
      "Biofuel",
      90,
      "EU",
      "Duplicate"
    );
    expect(duplicate).toEqual({ ok: false, value: 1 });
  });

  it("should enforce compliance and metadata rules", () => {
    const lowGhg = contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      10,
      "USA",
      "Test"
    );
    expect(lowGhg).toEqual({ ok: false, value: 9 });

    const longMetadata = "a".repeat(501);
    const invalidMeta = contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      longMetadata
    );
    expect(invalidMeta).toEqual({ ok: false, value: 6 });
  });

  it("should allow transfer of certificate", () => {
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test"
    );

    const transfer = contract.transferCertificate(accounts.producer, 1, accounts.user1);
    expect(transfer).toEqual({ ok: true, value: true });

    const verify = contract.verifyOwnership(1, accounts.user1);
    expect(verify).toEqual({ ok: true, value: true });
  });

  it("should allow retirement of certificate", () => {
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test"
    );

    const retire = contract.retireCertificate(accounts.producer, 1, "Used in transport");
    expect(retire).toEqual({ ok: true, value: true });

    const details = contract.getCertificateDetails(1);
    expect(details).toEqual({
      ok: true,
      value: expect.objectContaining({ retired: true, retirementReason: "Used in transport" }),
    });

    const transferAfterRetire = contract.transferCertificate(accounts.producer, 1, accounts.user1);
    expect(transferAfterRetire).toEqual({ ok: false, value: 5 });
  });

  it("should allow adding collaborator", () => {
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test"
    );

    const addCollab = contract.addCollaborator(accounts.producer, 1, accounts.user1, "Auditor", ["view", "verify"]);
    expect(addCollab).toEqual({ ok: true, value: true });

    const collab = contract.getCollaborator(1, accounts.user1);
    expect(collab).toEqual({
      ok: true,
      value: expect.objectContaining({ role: "Auditor" }),
    });
  });

  it("should allow logging compliance by verifier", () => {
    contract.addVerifier(accounts.deployer, accounts.verifier);
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test"
    );

    const log = contract.logCompliance(accounts.verifier, 1, true, "Passed audit", 1);
    expect(log).toEqual({ ok: true, value: true });

    const logDetails = contract.getComplianceLog(1, 1);
    expect(logDetails).toEqual({
      ok: true,
      value: expect.objectContaining({ status: true, notes: "Passed audit" }),
    });
  });

  it("should prevent non-verifier from logging compliance", () => {
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test"
    );

    const log = contract.logCompliance(accounts.user1, 1, true, "Unauthorized", 1);
    expect(log).toEqual({ ok: false, value: 8 });
  });

  it("should allow registering version", () => {
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test"
    );

    const registerVer = contract.registerVersion(accounts.producer, 1, 2, mockNewHash, "Updated metrics");
    expect(registerVer).toEqual({ ok: true, value: true });

    const version = contract.getVersion(1, 2);
    expect(version).toEqual({
      ok: true,
      value: expect.objectContaining({ changes: "Updated metrics" }),
    });
  });

  it("should allow granting license", () => {
    contract.issueCertificate(
      accounts.producer,
      mockHash,
      1000,
      "Biodiesel",
      80,
      "USA",
      "Test"
    );

    const grant = contract.grantLicense(accounts.producer, 1, accounts.user1, 100, "Use for trading");
    expect(grant).toEqual({ ok: true, value: true });

    const license = contract.getLicense(1, accounts.user1);
    expect(license).toEqual({
      ok: true,
      value: expect.objectContaining({ terms: "Use for trading", active: true }),
    });
  });
});