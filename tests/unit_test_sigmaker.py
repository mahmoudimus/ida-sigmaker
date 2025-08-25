"""
test_cpu_features.py - Unit tests for CPU feature detection

Tests the CPUFeatureDetector class and related functionality with mocked system interfaces
to ensure reliable testing across different platforms and architectures.
"""

import os
import sys
import unittest

# Patch sigmaker's idaapi and idc import to avoid loading an unnecessary dependency using unittest.mock
from unittest.mock import MagicMock, patch

# Add the src directory to the path so we can import sigmaker
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Use a context manager to patch sys.modules before importing sigmaker
with patch.dict("sys.modules", {"idaapi": MagicMock(), "idc": MagicMock()}):
    import sigmaker

SIMDType = sigmaker.SIMDType
CPUFeatureDetector = sigmaker.CPUFeatureDetector
OSType = sigmaker.OSType
SystemInterface = sigmaker.SystemInterface
UnixLikeProcessorFeature = sigmaker.UnixLikeProcessorFeature
WindowsProcessorFeature = sigmaker.WindowsProcessorFeature
X86EmulationDetector = sigmaker.X86EmulationDetector


class MockSystemInterface(SystemInterface):
    """Mock system interface for testing different system configurations."""

    def __init__(self):
        self.platform_system = "Linux"
        self.platform_machine = "x86_64"
        self.sys_platform = "linux"
        self.env_vars = {}
        self.subprocess_outputs = {}
        self.file_contents = {}
        self.processor_features = {}

    def get_platform_system(self) -> str:
        return self.platform_system

    def get_platform_machine(self) -> str:
        return self.platform_machine

    def get_sys_platform(self) -> str:
        return self.sys_platform

    def get_env_var(self, name: str) -> str | None:
        return self.env_vars.get(name)

    def run_subprocess(
        self, cmd: list[str] | str, text: bool = True, stderr=None
    ) -> str:
        if isinstance(cmd, list):
            cmd_key = " ".join(cmd)
        else:
            cmd_key = cmd

        if cmd_key in self.subprocess_outputs:
            return self.subprocess_outputs[cmd_key]
        raise FileNotFoundError(f"Command not found: {cmd_key}")

    def read_file(
        self, path: str, encoding: str = "utf-8", errors: str = "ignore"
    ) -> str:
        if path in self.file_contents:
            return self.file_contents[path]
        raise FileNotFoundError(f"File not found: {path}")

    def is_processor_feature_present(self, feature: int) -> bool:
        return self.processor_features.get(feature, False)

    def is_running_in_docker(self) -> bool:
        """Mock Docker detection."""
        # Check environment variable first
        if self.get_env_var("SIGMAKER_DOCKER"):
            return True

        # Check /proc/mounts for Docker overlay filesystem
        try:
            mounts = self.read_file("/proc/mounts")
            return "docker" in mounts.lower() and "overlay" in mounts.lower()
        except Exception:
            return False

    def file_exists(self, path: str) -> bool:
        """Mock file existence check."""
        return path in self.file_contents


class TestSIMDType(unittest.TestCase):
    """Test the SIMDType enum and its methods."""

    def test_of_type_valid_inputs(self):
        """Test SIMDType.of_type with valid string inputs."""
        test_cases = [
            ("none", SIMDType.NONE),
            ("0", SIMDType.NONE),
            ("basic", SIMDType.BASIC),
            ("1", SIMDType.BASIC),
            ("simd", SIMDType.SIMD),
            ("2", SIMDType.SIMD),
            ("simd2", SIMDType.SIMD2),
            ("3", SIMDType.SIMD2),
            ("simd512", SIMDType.SIMD512),
            ("4", SIMDType.SIMD512),
        ]

        for input_str, expected in test_cases:
            with self.subTest(input_str=input_str):
                result = SIMDType.of_type(input_str)
                self.assertEqual(result, expected)

    def test_of_type_case_insensitive(self):
        """Test that SIMDType.of_type is case insensitive."""
        test_cases = [
            "SIMD",
            "Simd",
            "sImD",
            "SIMD2",
            "simd2",
            "SiMd2",
            "SIMD512",
            "simd512",
            "SiMd512",
        ]
        for input_str in test_cases:
            with self.subTest(input_str=input_str):
                result = SIMDType.of_type(input_str)
                self.assertIsNotNone(result)

    def test_of_type_invalid_inputs(self):
        """Test SIMDType.of_type with invalid inputs."""
        invalid_inputs = [None, "", "invalid", "5", "sse", " "]
        for input_str in invalid_inputs:
            with self.subTest(input_str=input_str):
                result = SIMDType.of_type(input_str)
                self.assertIsNone(result)

    def test_of_type_legacy_avx_not_supported(self):
        """Test that legacy AVX values are no longer supported."""
        legacy_inputs = ["avx", "avx2", "avx512", "avx-512"]
        for input_str in legacy_inputs:
            with self.subTest(input_str=input_str):
                result = SIMDType.of_type(input_str)
                self.assertIsNone(
                    result, f"Legacy AVX value '{input_str}' should not be supported"
                )


class TestCPUFeatureDetector(unittest.TestCase):
    """Test the CPUFeatureDetector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_get_os_type_windows(self):
        """Test OS detection for Windows."""
        test_cases = ["Windows", "windows", "Windows NT"]
        for system_name in test_cases:
            with self.subTest(system_name=system_name):
                self.mock_system.platform_system = system_name
                result = self.detector.get_os_type()
                self.assertEqual(result, OSType.WINDOWS)

    def test_get_os_type_linux(self):
        """Test OS detection for Linux."""
        self.mock_system.platform_system = "Linux"
        result = self.detector.get_os_type()
        self.assertEqual(result, OSType.LINUX)

    def test_get_os_type_darwin(self):
        """Test OS detection for macOS."""
        self.mock_system.platform_system = "Darwin"
        result = self.detector.get_os_type()
        self.assertEqual(result, OSType.DARWIN)

    def test_get_os_type_other(self):
        """Test OS detection for other systems."""
        self.mock_system.platform_system = "FreeBSD"
        result = self.detector.get_os_type()
        self.assertEqual(result, OSType.OTHER)

    def test_is_x86_like(self):
        """Test x86 architecture detection."""
        x86_machines = ["x86_64", "amd64", "i686", "x86", "X86_64", "AMD64"]
        for machine in x86_machines:
            with self.subTest(machine=machine):
                self.mock_system.platform_machine = machine
                result = self.detector.is_x86_like()
                self.assertTrue(result)

    def test_is_not_x86_like(self):
        """Test non-x86 architecture detection."""
        non_x86_machines = ["aarch64", "arm64", "armv8", "ppc64", "s390x"]
        for machine in non_x86_machines:
            with self.subTest(machine=machine):
                self.mock_system.platform_machine = machine
                result = self.detector.is_x86_like()
                self.assertFalse(result)

    def test_is_arm_like(self):
        """Test ARM architecture detection."""
        arm_machines = ["aarch64", "arm64", "armv8", "armv7", "arm", "ARM64", "AARCH64"]
        for machine in arm_machines:
            with self.subTest(machine=machine):
                self.mock_system.platform_machine = machine
                result = self.detector.is_arm_like()
                self.assertTrue(result)

    def test_is_not_arm_like(self):
        """Test non-ARM architecture detection."""
        non_arm_machines = ["x86_64", "amd64", "i686", "ppc64", "s390x"]
        for machine in non_arm_machines:
            with self.subTest(machine=machine):
                self.mock_system.platform_machine = machine
                result = self.detector.is_arm_like()
                self.assertFalse(result)


class TestWindowsSIMDDetection(unittest.TestCase):
    """Test Windows-specific SIMD detection."""

    def setUp(self):
        """Set up test fixtures for Windows testing."""
        self.mock_system = MockSystemInterface()
        self.mock_system.platform_system = "Windows"
        self.mock_system.platform_machine = "x86_64"
        self.mock_system.sys_platform = "win32"
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_windows_simd512_support(self):
        """Test Windows SIMD512 (AVX512) detection."""
        self.mock_system.processor_features = {39: True, 40: True, 41: True}
        result = WindowsProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD512)

    def test_windows_simd2_support(self):
        """Test Windows SIMD2 (AVX2) detection."""
        self.mock_system.processor_features = {39: True, 40: True, 41: False}
        result = WindowsProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)

    def test_windows_simd_support(self):
        """Test Windows SIMD (AVX) detection."""
        self.mock_system.processor_features = {39: True, 40: False, 41: False}
        result = WindowsProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD)

    def test_windows_basic_support(self):
        """Test Windows basic (no SIMD) detection."""
        self.mock_system.processor_features = {39: False, 40: False, 41: False}
        result = WindowsProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.BASIC)

    def test_non_windows_platform(self):
        """Test that non-Windows platforms return BASIC."""
        self.mock_system.sys_platform = "linux"
        result = WindowsProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.BASIC)


class TestMacOSSIMDDetection(unittest.TestCase):
    """Test macOS-specific SIMD detection."""

    def setUp(self):
        """Set up test fixtures for macOS testing."""
        self.mock_system = MockSystemInterface()
        self.mock_system.platform_system = "Darwin"
        self.mock_system.platform_machine = "x86_64"
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_macos_x86_simd512_support(self):
        """Test macOS x86 SIMD512 (AVX512) detection."""
        self.mock_system.subprocess_outputs = {
            "sysctl -n machdep.cpu.features machdep.cpu.leaf7_features": "avx avx2 avx512f avx512cd"
        }
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD512)

    def test_macos_x86_simd2_support(self):
        """Test macOS x86 SIMD2 (AVX2) detection."""
        self.mock_system.subprocess_outputs = {
            "sysctl -n machdep.cpu.features machdep.cpu.leaf7_features": "avx avx2"
        }
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)

    def test_macos_x86_simd_support(self):
        """Test macOS x86 SIMD (AVX) detection."""
        self.mock_system.subprocess_outputs = {
            "sysctl -n machdep.cpu.features machdep.cpu.leaf7_features": "avx sse4.1 sse4.2"
        }
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD)

    def test_macos_x86_basic_support(self):
        """Test macOS x86 basic (no SIMD) detection."""
        self.mock_system.subprocess_outputs = {
            "sysctl -n machdep.cpu.features machdep.cpu.leaf7_features": "sse4.1 sse4.2"
        }
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.BASIC)

    def test_macos_arm_neon_support(self):
        """Test macOS ARM NEON detection (mapped to SIMD2)."""
        self.mock_system.platform_machine = "arm64"
        self.mock_system.subprocess_outputs = {"sysctl -n hw.optional.neon": "1"}
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)

    def test_macos_arm_no_neon_support(self):
        """Test macOS ARM without NEON detection."""
        self.mock_system.platform_machine = "arm64"
        self.mock_system.subprocess_outputs = {"sysctl -n hw.optional.neon": "0"}
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.BASIC)


class TestLinuxSIMDDetection(unittest.TestCase):
    """Test Linux-specific SIMD detection."""

    def setUp(self):
        """Set up test fixtures for Linux testing."""
        self.mock_system = MockSystemInterface()
        self.mock_system.platform_system = "Linux"
        self.mock_system.platform_machine = "x86_64"
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_linux_cpuinfo_simd512_support(self):
        """Test Linux SIMD512 (AVX512) detection via /proc/cpuinfo."""
        self.mock_system.file_contents = {
            "/proc/cpuinfo": "flags: avx avx2 avx512f avx512cd avx512bw"
        }
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD512)

    def test_linux_cpuinfo_simd2_support(self):
        """Test Linux SIMD2 (AVX2) detection via /proc/cpuinfo."""
        self.mock_system.file_contents = {
            "/proc/cpuinfo": "flags: sse4_1 sse4_2 avx avx2"
        }
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)

    def test_linux_cpuinfo_simd_support(self):
        """Test Linux SIMD (AVX) detection via /proc/cpuinfo."""
        self.mock_system.file_contents = {"/proc/cpuinfo": "flags: sse4_1 sse4_2 avx "}
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD)

    def test_linux_lscpu_fallback_simd2(self):
        """Test Linux SIMD2 (AVX2) detection via lscpu fallback."""
        # Simulate /proc/cpuinfo not being readable
        self.mock_system.subprocess_outputs = {"lscpu": "Flags: sse4_1 sse4_2 avx avx2"}
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)

    def test_linux_basic_support(self):
        """Test Linux basic (no SIMD) detection."""
        self.mock_system.file_contents = {"/proc/cpuinfo": "flags: sse4_1 sse4_2"}
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.BASIC)


class TestEnvironmentOverride(unittest.TestCase):
    """Test environment variable override functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_env_override_simd512(self):
        """Test environment override for SIMD512."""
        self.mock_system.env_vars = {"SIGMAKER_SIMD": "simd512"}
        cpu_feature = self.detector.get_cpu_simd_support()
        os_type, simd_type = cpu_feature.os_type, cpu_feature.simd_type
        self.assertEqual(simd_type, SIMDType.SIMD512)

    def test_env_override_simd2(self):
        """Test environment override for SIMD2."""
        self.mock_system.env_vars = {"SIGMAKER_SIMD": "simd2"}
        cpu_feature = self.detector.get_cpu_simd_support()
        os_type, simd_type = cpu_feature.os_type, cpu_feature.simd_type
        self.assertEqual(simd_type, SIMDType.SIMD2)

    def test_env_override_numeric(self):
        """Test environment override with numeric values."""
        test_cases = [
            ("0", SIMDType.NONE),
            ("1", SIMDType.BASIC),
            ("2", SIMDType.SIMD),
            ("3", SIMDType.SIMD2),
            ("4", SIMDType.SIMD512),
        ]

        for env_val, expected_simd in test_cases:
            with self.subTest(env_val=env_val):
                self.mock_system.env_vars = {"SIGMAKER_SIMD": env_val}
                self.detector.clear_cache()  # Clear cache between tests
                cpu_feature = self.detector.get_cpu_simd_support.__wrapped__(
                    self.detector
                )
                os_type, simd_type = cpu_feature.os_type, cpu_feature.simd_type
                self.assertEqual(simd_type, expected_simd)

    def test_no_env_override(self):
        """Test that detection works when no environment override is set."""
        self.mock_system.env_vars = {}
        self.mock_system.platform_machine = "arm64"  # Should result in BASIC for ARM
        cpu_feature = self.detector.get_cpu_simd_support()
        os_type, simd_type = cpu_feature.os_type, cpu_feature.simd_type
        self.assertEqual(simd_type, SIMDType.BASIC)


class TestARMArchitecture(unittest.TestCase):
    """Test ARM architecture handling."""

    def setUp(self):
        """Set up test fixtures for ARM testing."""
        self.mock_system = MockSystemInterface()
        self.mock_system.platform_machine = "aarch64"
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_arm_neon_detection(self):
        """Test that ARM architectures detect NEON properly on macOS."""
        self.mock_system.platform_system = "Darwin"
        self.mock_system.platform_machine = "arm64"
        self.mock_system.subprocess_outputs = {"sysctl -n hw.optional.neon": "1"}

        self.detector.clear_cache()
        cpu_feature = self.detector.get_cpu_simd_support.__wrapped__(self.detector)
        os_type, simd_type = cpu_feature.os_type, cpu_feature.simd_type
        self.assertEqual(simd_type, SIMDType.SIMD2)

    def test_arm_no_neon_detection(self):
        """Test that ARM architectures without NEON return BASIC."""
        self.mock_system.platform_system = "Darwin"
        self.mock_system.platform_machine = "arm64"
        self.mock_system.subprocess_outputs = {"sysctl -n hw.optional.neon": "0"}

        self.detector.clear_cache()
        cpu_feature = self.detector.get_cpu_simd_support.__wrapped__(self.detector)
        os_type, simd_type = cpu_feature.os_type, cpu_feature.simd_type
        self.assertEqual(simd_type, SIMDType.BASIC)

    def test_arm_linux_basic(self):
        """Test that ARM on Linux returns BASIC (no special detection)."""
        arm_machines = ["aarch64", "arm64", "armv8", "armv7", "arm"]
        for machine in arm_machines:
            with self.subTest(machine=machine):
                self.mock_system.platform_system = "Linux"
                self.mock_system.platform_machine = machine
                self.detector.clear_cache()
                cpu_feature = self.detector.get_cpu_simd_support.__wrapped__(
                    self.detector
                )
                os_type, simd_type = cpu_feature.os_type, cpu_feature.simd_type
                self.assertEqual(simd_type, SIMDType.BASIC)


class TestCaching(unittest.TestCase):
    """Test caching functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_caching_enabled(self):
        """Test that caching works when enabled."""
        # First call should populate cache
        result1 = self.detector.get_cpu_simd_support()

        # Change the mock system but cache should return same result
        self.mock_system.platform_machine = "different_arch"
        result2 = self.detector.get_cpu_simd_support()

        self.assertEqual(result1, result2)

    def test_caching_disabled(self):
        """Test that caching can be disabled."""
        # First call - configure for Windows x86_64 with AVX2
        self.mock_system.platform_system = "Windows"
        self.mock_system.platform_machine = "x86_64"
        self.mock_system.sys_platform = "win32"
        self.mock_system.processor_features = {39: True, 40: True, 41: False}
        result1 = self.detector.get_cpu_simd_support.__wrapped__(self.detector)

        # Change system and call again with cache disabled - ARM system
        self.mock_system.platform_system = "Darwin"
        self.mock_system.platform_machine = "arm64"
        self.mock_system.sys_platform = "darwin"
        result2 = self.detector.get_cpu_simd_support.__wrapped__(self.detector)

        # Results should be different since cache was disabled
        self.assertNotEqual(result1, result2)

    def test_cache_clearing(self):
        """Test that cache can be cleared."""
        # Populate cache - configure for Windows x86_64 with AVX2
        self.mock_system.platform_system = "Windows"
        self.mock_system.platform_machine = "x86_64"
        self.mock_system.sys_platform = "win32"
        self.mock_system.processor_features = {39: True, 40: True, 41: False}
        result1 = self.detector.get_cpu_simd_support()

        # Clear cache and change system - ARM system
        self.detector.clear_cache()
        self.mock_system.platform_system = "Darwin"
        self.mock_system.platform_machine = "arm64"
        self.mock_system.sys_platform = "darwin"
        result2 = self.detector.get_cpu_simd_support()

        # Results should be different since cache was cleared
        self.assertNotEqual(result1, result2)


class TestSIMD2Available(unittest.TestCase):
    """Test the is_simd2_available convenience method."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_simd2_available_true(self):
        """Test that SIMD2+ types return True for is_simd2_available."""
        simd2_plus_types = [SIMDType.SIMD2, SIMDType.SIMD512]
        for simd_type in simd2_plus_types:
            with self.subTest(simd_type=simd_type):
                self.mock_system.env_vars = {
                    "SIGMAKER_SIMD": str(simd_type.value - 1)
                }  # Convert to numeric
                self.detector.clear_cache()
                result = self.detector.is_simd2_available()
                self.assertTrue(result)

    def test_simd2_available_false(self):
        """Test that sub-SIMD2 types return False for is_simd2_available."""
        sub_simd2_types = [SIMDType.NONE, SIMDType.BASIC, SIMDType.SIMD]
        for simd_type in sub_simd2_types:
            with self.subTest(simd_type=simd_type):
                self.mock_system.env_vars = {
                    "SIGMAKER_SIMD": str(simd_type.value - 1)
                }  # Convert to numeric
                self.detector.clear_cache()
                result = self.detector.is_simd2_available()
                self.assertFalse(result)


class TestErrorHandling(unittest.TestCase):
    """Test error handling in various scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_subprocess_error_fallback(self):
        """Test that subprocess errors fall back to BASIC."""
        self.mock_system.platform_system = "Darwin"
        self.mock_system.platform_machine = "x86_64"
        # Don't set subprocess_outputs, so it will raise FileNotFoundError

        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.BASIC)

    def test_file_read_error_fallback(self):
        """Test that file read errors fall back to subprocess or BASIC."""
        self.mock_system.platform_system = "Linux"
        self.mock_system.platform_machine = "x86_64"
        # Don't set file_contents, so reading /proc/cpuinfo will fail
        # Also don't set subprocess_outputs, so lscpu will also fail

        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.BASIC)


class TestDockerDetection(unittest.TestCase):
    """Test Docker container detection functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_docker_detection_via_env_var(self):
        """Test Docker detection via SIGMAKER_DOCKER environment variable."""
        self.mock_system.env_vars["SIGMAKER_DOCKER"] = "1"
        result = self.mock_system.is_running_in_docker()
        self.assertTrue(result)

    def test_docker_detection_via_proc_mounts(self):
        """Test Docker detection via /proc/mounts overlay filesystem."""
        docker_mounts = """
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/l/abc123,upperdir=/var/lib/docker/overlay2/xyz789/diff,workdir=/var/lib/docker/overlay2/xyz789/work 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
"""
        self.mock_system.file_contents["/proc/mounts"] = docker_mounts
        result = self.mock_system.is_running_in_docker()
        self.assertTrue(result)

    def test_docker_detection_no_docker(self):
        """Test Docker detection when not in Docker."""
        regular_mounts = """
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
"""
        self.mock_system.file_contents["/proc/mounts"] = regular_mounts
        result = self.mock_system.is_running_in_docker()
        self.assertFalse(result)

    def test_docker_detection_proc_mounts_missing(self):
        """Test Docker detection when /proc/mounts is not accessible."""
        # Don't set file_contents for /proc/mounts
        result = self.mock_system.is_running_in_docker()
        self.assertFalse(result)


class TestEmulatedX86Detection(unittest.TestCase):
    """Test detection of emulated x86 on ARM systems."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_emulated_x86_detection_rosetta(self):
        """Test detection of Rosetta emulation (Apple Silicon)."""
        # Set up Docker environment
        self.mock_system.env_vars["SIGMAKER_DOCKER"] = "1"

        # Mock lscpu output for Rosetta emulation
        lscpu_output = """
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              8
Vendor ID:           Apple
Model name:          Apple M1 Pro
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves arat md_clear arch_capabilities asimd
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = X86EmulationDetector.is_emulated_x86_on_arm(self.mock_system)
        self.assertTrue(result)

    def test_emulated_x86_detection_neon_flags(self):
        """Test detection via NEON flags in emulated environment."""
        # Set up Docker environment
        self.mock_system.env_vars["SIGMAKER_DOCKER"] = "1"

        # Mock lscpu output with NEON but claiming x86_64
        lscpu_output = """
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Flags:               sse sse2 ssse3 sse4_1 sse4_2 avx avx2 neon asimd
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = X86EmulationDetector.is_emulated_x86_on_arm(self.mock_system)
        self.assertTrue(result)

    def test_emulated_x86_detection_not_docker(self):
        """Test that emulation detection returns False when not in Docker."""
        # Don't set Docker environment
        lscpu_output = """
Architecture:        x86_64
Vendor ID:           Apple
Flags:               asimd neon
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = X86EmulationDetector.is_emulated_x86_on_arm(self.mock_system)
        self.assertFalse(result)

    def test_emulated_x86_detection_real_x86(self):
        """Test that real x86 systems are not detected as emulated."""
        # Set up Docker environment
        self.mock_system.env_vars["SIGMAKER_DOCKER"] = "1"

        # Mock lscpu output for real Intel x86
        lscpu_output = """
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Vendor ID:           GenuineIntel
Model name:          Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = X86EmulationDetector.is_emulated_x86_on_arm(self.mock_system)
        self.assertFalse(result)

    def test_emulated_x86_detection_subprocess_error(self):
        """Test emulation detection when subprocess fails."""
        # Set up Docker environment
        self.mock_system.env_vars["SIGMAKER_DOCKER"] = "1"

        # Don't set subprocess_outputs, so lscpu will fail
        result = X86EmulationDetector.is_emulated_x86_on_arm(self.mock_system)
        self.assertFalse(result)


class TestNeonSIMDMapping(unittest.TestCase):
    """Test mapping of ARM NEON features to SIMD equivalents."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_neon_to_simd2_mapping(self):
        """Test that NEON/ASIMD features map to SIMD2."""
        lscpu_output = """
Architecture:        aarch64
Flags:               asimd evtstrm aes pmull sha1 sha2 crc32
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = X86EmulationDetector.get_emulated_simd_support_from_neon(
            self.mock_system
        )
        self.assertEqual(result, SIMDType.SIMD2)

    def test_neon_legacy_to_simd2_mapping(self):
        """Test that legacy NEON flags also map to SIMD2."""
        lscpu_output = """
Architecture:        armv7l
Flags:               half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = X86EmulationDetector.get_emulated_simd_support_from_neon(
            self.mock_system
        )
        self.assertEqual(result, SIMDType.SIMD2)

    def test_no_neon_to_basic_mapping(self):
        """Test that ARM without NEON maps to BASIC."""
        lscpu_output = """
Architecture:        armv6l
Flags:               half thumb fastmult vfp edsp vfpv2
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = X86EmulationDetector.get_emulated_simd_support_from_neon(
            self.mock_system
        )
        self.assertEqual(result, SIMDType.BASIC)

    def test_neon_mapping_subprocess_error(self):
        """Test NEON mapping when subprocess fails."""
        # Don't set subprocess_outputs, so lscpu will fail
        result = X86EmulationDetector.get_emulated_simd_support_from_neon(
            self.mock_system
        )
        self.assertEqual(result, SIMDType.BASIC)


class TestEmulatedSIMDDetection(unittest.TestCase):
    """Test integrated emulated SIMD detection in get_nix_simd_support."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_system = MockSystemInterface()
        self.detector = CPUFeatureDetector(self.mock_system)

    def test_emulated_x86_uses_neon_mapping(self):
        """Test that emulated x86 on ARM uses NEON mapping for SIMD detection."""
        # Set up Linux Docker environment with emulation
        self.mock_system.platform_system = "Linux"
        self.mock_system.platform_machine = "x86_64"
        self.mock_system.env_vars["SIGMAKER_DOCKER"] = "1"

        # Mock lscpu for emulated environment
        lscpu_output = """
Architecture:        x86_64
Vendor ID:           Apple
Flags:               sse sse2 avx avx2 asimd neon
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_output

        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)

    def test_real_linux_x86_uses_normal_detection(self):
        """Test that real Linux x86 systems use normal SIMD detection."""
        # Set up Linux environment without Docker
        self.mock_system.platform_system = "Linux"
        self.mock_system.platform_machine = "x86_64"

        # Mock /proc/cpuinfo for real Intel system
        cpuinfo = """
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 158
model name	: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d
"""
        self.mock_system.file_contents["/proc/cpuinfo"] = cpuinfo

        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)

    def test_emulated_environment_priority(self):
        """Test that emulated environment detection takes priority over normal detection."""
        # Set up environment that would normally detect AVX512 but is emulated
        self.mock_system.platform_system = "Linux"
        self.mock_system.platform_machine = "x86_64"
        self.mock_system.env_vars["SIGMAKER_DOCKER"] = "1"

        # Mock lscpu for emulated environment (claims AVX512 but has Apple vendor)
        lscpu_emulation = """
Architecture:        x86_64
Vendor ID:           Apple
Flags:               avx avx2 avx512f avx512dq avx512cd avx512bw avx512vl asimd neon
"""
        self.mock_system.subprocess_outputs["lscpu"] = lscpu_emulation

        # Also set /proc/cpuinfo that would normally indicate AVX512
        cpuinfo_fake = """
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves arat md_clear arch_capabilities avx512f avx512dq avx512cd avx512bw avx512vl
"""
        self.mock_system.file_contents["/proc/cpuinfo"] = cpuinfo_fake

        # Should use emulated detection (AVX2 from NEON) instead of normal detection (AVX512)
        result = UnixLikeProcessorFeature.supported_simd_type(self.mock_system)
        self.assertEqual(result, SIMDType.SIMD2)


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)
