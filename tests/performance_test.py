import array
import gc
import logging
import pathlib
import shutil
import sys
import tempfile
import time
import unittest
import unittest.mock
import warnings

# Context manager to suppress warnings from IDA Pro modules during import
with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore", category=ResourceWarning, message=".*unclosed file.*"
    )
    warnings.filterwarnings(
        "ignore", category=DeprecationWarning, message=".*swigvarlink.*"
    )
    # CRITICAL: Import idapro as the FIRST import for idalib
    import idapro
    import idaapi

    # Add both src directory and IDA plugins directory to Python path
    sys.path.insert(0, str((pathlib.Path(__file__).resolve().parents[1] / "src")))
    sys.path.insert(0, "/root/.idapro/plugins")
    import sigmaker  # noqa: E402


# Set up logging for tests
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def code_segment_for_platform(platform_id: int):
    if platform_id == idaapi.PLFM_386:
        return idaapi.get_segm_by_name(".text")
    elif platform_id == idaapi.PLFM_ARM:
        return idaapi.get_segm_by_name("__TEXT")
    else:
        return None


class TestBenchmarkPerformance(unittest.TestCase):
    """Performance benchmark tests using time.perf_counter()."""

    @classmethod
    def setUpClass(cls):
        cls.tests_dir = pathlib.Path(__file__).parent
        cls.binary_path = cls.tests_dir / "resources/bin/test_binary.exe"

        if not cls.binary_path.exists():
            raise unittest.SkipTest("Test binary not available")

        cls.tempdir = pathlib.Path(tempfile.mkdtemp())
        cls.temp_binary_path = cls.tempdir / cls.binary_path.name
        shutil.copy(cls.binary_path, cls.temp_binary_path)

        # Open database once for all tests
        result = idapro.open_database(str(cls.temp_binary_path), True)
        if result != 0:
            raise unittest.SkipTest(f"Failed to open database. Result code: {result}")

        idaapi.auto_wait()
        cls.database_opened = True
        seg = code_segment_for_platform(idaapi.ph_get_id())
        cls.min_ea = seg.start_ea if seg else idaapi.inf_get_min_ea()
        cls.max_ea = seg.end_ea if seg else idaapi.inf_get_max_ea()

        cls.ida_available = True

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "database_opened") and cls.database_opened:
            idapro.close_database()
        if cls.tempdir and cls.tempdir.exists():
            shutil.rmtree(cls.tempdir)

    def get_code_address(self) -> int | None:
        """Get a code address for testing."""
        if not self.ida_available:
            return 0x1500  # Return a mock address for testing

        for ea in range(self.min_ea, min(self.min_ea + 0x1000, self.max_ea)):
            if idaapi.is_code(idaapi.get_flags(ea)):
                return ea
        return None

    def benchmark_signature_generation_single(self, iterations: int = 5) -> dict:
        """Benchmark single address signature generation."""

        signature_maker = sigmaker.SignatureMaker()
        func_ea = self.get_code_address()

        if not func_ea:
            self.skipTest("No code address found for benchmarking")

        ctx = sigmaker.Context(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=True,
            wildcard_optimized=False,
        )

        times = []
        for _ in range(iterations):
            start_time = time.perf_counter()
            result = signature_maker.make_signature(func_ea, ctx)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        return {
            "operation": "signature_generation_single",
            "iterations": iterations,
            "times": times,
            "min_time": min(times),
            "max_time": max(times),
            "avg_time": sum(times) / len(times),
            "signature_length": len(result.signature),
        }

    def benchmark_signature_generation_range(self, iterations: int = 5) -> dict:
        """Benchmark range-based signature generation."""

        signature_maker = sigmaker.SignatureMaker()
        start_ea = self.get_code_address()

        if not start_ea:
            self.skipTest("No code address found for benchmarking")

        end_ea = start_ea + 32  # Small range for consistent benchmarking
        ctx = sigmaker.Context(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
        )

        times = []
        for _ in range(iterations):
            start_time = time.perf_counter()
            result = signature_maker.make_signature(start_ea, ctx, end=end_ea)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        return {
            "operation": "signature_generation_range",
            "iterations": iterations,
            "times": times,
            "min_time": min(times),
            "max_time": max(times),
            "avg_time": sum(times) / len(times),
            "signature_length": len(result.signature),
            "range_size": end_ea - start_ea,
        }

    def benchmark_signature_search(self, iterations: int = 5) -> dict:
        """Benchmark signature searching."""
        if not self.ida_available:
            self.skipTest("IDA Pro API not available for benchmarking")
        # Create a common signature pattern to search for
        search_patterns = ["C3", "48 89", "8B 45", "C7 44"]

        times = []
        total_matches = 0

        for _ in range(iterations):
            start_time = time.perf_counter()
            for pattern in search_patterns:
                searcher = sigmaker.SignatureSearcher.from_signature(pattern)
                ctx = sigmaker.Context(
                    output_format=sigmaker.SignatureType.IDA,
                    wildcard_operands=False,
                    continue_outside_of_function=False,
                    wildcard_optimized=False,
                )
                results = searcher.search(ctx)
                total_matches += len(results.matches)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        return {
            "operation": "signature_search",
            "iterations": iterations,
            "patterns_tested": len(search_patterns),
            "times": times,
            "min_time": min(times),
            "max_time": max(times),
            "avg_time": sum(times) / len(times),
            "total_matches_found": total_matches,
        }

    def benchmark_simd_vs_python_scanning(self, iterations: int = 10) -> dict:
        """Benchmark SIMD-accelerated scanning vs regular Python scanning."""
        if not sigmaker.SIMD_SPEEDUP_AVAILABLE:
            self.skipTest("SIMD speedup not available")

        # Create larger test data for meaningful comparison
        test_data = array.array("B", [0x48, 0x8B, 0xC4, 0x48, 0x89, 0x45] * 5000)
        data_view = memoryview(test_data)

        # Test different signature patterns
        patterns = ["48 8B", "8B C4", "C4 48", "89 45"]

        # Benchmark SIMD (Cython) scanning
        simd_times = []
        for _ in range(iterations):
            start_time = time.perf_counter()
            for pattern in patterns:
                sig = sigmaker._SimdSignature(pattern)
                sigmaker._simd_scan_bytes(data_view, sig)
            end_time = time.perf_counter()
            simd_times.append(end_time - start_time)

        # Benchmark regular Python scanning (simulated)
        python_times = []
        for _ in range(iterations):
            start_time = time.perf_counter()
            for pattern in patterns:
                # Convert pattern to bytes for comparison
                pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
                # Simple Python byte-by-byte search
                for i in range(len(test_data) - len(pattern_bytes) + 1):
                    if test_data[i : i + len(pattern_bytes)] == pattern_bytes:
                        break  # Just find first match
            end_time = time.perf_counter()
            python_times.append(end_time - start_time)

        return {
            "operation": "simd_vs_python_scanning",
            "iterations": iterations,
            "patterns_tested": len(patterns),
            "data_size": len(test_data),
            "simd_times": simd_times,
            "python_times": python_times,
            "simd_avg": sum(simd_times) / len(simd_times),
            "python_avg": sum(python_times) / len(python_times),
            "speedup_factor": sum(python_times) / sum(simd_times),
        }

    def test_performance_benchmarks(self):
        """Run all performance benchmarks and display results."""
        print("\n" + "=" * 80)
        print("PERFORMANCE BENCHMARKS")
        print("=" * 80)

        benchmarks = [
            self.benchmark_signature_generation_single,
            self.benchmark_signature_generation_range,
            self.benchmark_signature_search,
        ]

        if sigmaker.SIMD_SPEEDUP_AVAILABLE:
            benchmarks.append(self.benchmark_simd_vs_python_scanning)
            # Add focused SIMD speedup test
            print("\n🎯 RUNNING FOCUSED SIMD SPEEDUP TEST...")
            try:
                self.test_simd_speedup_focused()
            except Exception as e:
                print(f"Focused SIMD test failed: {e}")

        for benchmark_func in benchmarks:
            try:
                result = benchmark_func()

                if result["operation"] == "simd_vs_python_scanning":
                    # Special handling for SIMD vs Python comparison
                    print(f"\n🚀 {result['operation'].replace('_', ' ').title()}")
                    print(f"   Iterations: {result['iterations']}")
                    print(f"   Data Size: {result['data_size']} bytes")
                    print(f"   Patterns Tested: {result['patterns_tested']}")
                    print(f"   SIMD Avg Time: {result['simd_avg']:.6f}s")
                    print(f"   Python Avg Time: {result['python_avg']:.6f}s")
                    print(f"   Speedup Factor: {result['speedup_factor']:.2f}x")
                else:
                    # Standard benchmark display
                    print(f"\n📊 {result['operation'].replace('_', ' ').title()}")
                    print(f"   Iterations: {result['iterations']}")
                    print(f"   Best Time: {result['min_time']:.4f}s")
                    print(f"   Worst Time: {result['max_time']:.4f}s")
                    print(f"   Average Time: {result['avg_time']:.4f}s")
                    print(f"   Min Time: {result['min_time']:.6f}s")
                    print(f"   Max Time: {result['max_time']:.6f}s")
                    print(f"   Avg Time: {result['avg_time']:.6f}s")
                    # Print additional context
                    for key, value in result.items():
                        if key not in [
                            "operation",
                            "iterations",
                            "times",
                            "min_time",
                            "max_time",
                            "avg_time",
                        ]:
                            print(f"   {key}: {value}")

            except Exception as e:
                print(f"\n❌ {benchmark_func.__name__}: Failed - {e}")

        print("\n" + "=" * 80)
        print("BENCHMARKS COMPLETE")
        print("=" * 80)

    def test_detailed_signature_generation_benchmark(self):
        """Detailed benchmark for signature generation with different configurations."""

        signature_maker = sigmaker.SignatureMaker()
        func_ea = self.get_code_address()

        if not func_ea:
            self.skipTest("No code address found for benchmarking")

        configurations = [
            {"wildcard_operands": False, "wildcard_optimized": False, "name": "Basic"},
            {
                "wildcard_operands": True,
                "wildcard_optimized": False,
                "name": "With Wildcards",
            },
            {
                "wildcard_operands": True,
                "wildcard_optimized": True,
                "name": "Optimized Wildcards",
            },
        ]

        print("\n" + "=" * 60)
        print("DETAILED SIGNATURE GENERATION BENCHMARK")
        print("=" * 60)

        for config in configurations:
            ctx = sigmaker.Context(
                output_format=sigmaker.SignatureType.IDA,
                wildcard_operands=config["wildcard_operands"],
                continue_outside_of_function=True,
                wildcard_optimized=config["wildcard_optimized"],
            )

            times = []
            signature_lengths = []

            # Run multiple times for statistical significance
            for _ in range(10):
                start_time = time.perf_counter()
                result = signature_maker.make_signature(func_ea, ctx)
                end_time = time.perf_counter()

                times.append(end_time - start_time)
                signature_lengths.append(len(result.signature))

            avg_time = sum(times) / len(times)
            avg_length = sum(signature_lengths) / len(signature_lengths)

            print(f"\n⚡ {config['name']} Configuration:")
            print(f"   Average Time: {avg_time:.4f}s")
            print(f"   Avg Signature Length: {avg_length:.1f} bytes")
            print(f"   Min Time: {min(times):.6f}s")
            print(f"   Max Time: {max(times):.6f}s")
            print(
                f"   Std Dev: {(sum((t - avg_time)**2 for t in times) / len(times))**0.5:.6f}s"
            )

    def test_memory_usage_benchmark(self):
        """Benchmark memory usage patterns."""
        if not self.ida_available:
            self.skipTest("IDA Pro API not available for benchmarking")

        signature_maker = sigmaker.SignatureMaker()
        func_ea = self.get_code_address()

        if not func_ea:
            self.skipTest("No code address found for benchmarking")

        ctx = sigmaker.Context(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=True,
            wildcard_optimized=False,
        )

        print("\n" + "=" * 50)
        print("MEMORY USAGE BENCHMARK")
        print("=" * 50)

        # Force garbage collection before starting
        gc.collect()

        times = []
        for i in range(50):  # Many iterations to see memory patterns
            start_time = time.perf_counter()
            result = signature_maker.make_signature(func_ea, ctx)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

            if (i + 1) % 10 == 0:
                avg_time = sum(times[-10:]) / 10
                print(f"   Iteration {i+1:2d}: {avg_time:.6f}s (avg of last 10)")
        print(f"\n📈 Final Statistics:")
        print(f"   Overall Average: {sum(times)/len(times):.6f}s")
        print(f"   Min Time: {min(times):.6f}s")
        print(f"   Max Time: {max(times):.6f}s")

    def test_simd_speedup_focused(self):
        """Focused test demonstrating SIMD speedup for signature searching."""
        if not sigmaker.SIMD_SPEEDUP_AVAILABLE:
            self.skipTest(
                "SIMD speedup not available - this test demonstrates the optimization"
            )

        if not self.ida_available:
            self.skipTest("IDA Pro API not available for benchmarking")

        # Create large test data to show SIMD benefits
        # Use repeating patterns to ensure multiple matches
        pattern = [0x48, 0x8B, 0x45, 0xF8, 0x48, 0x89, 0x45, 0xE8] * 1000
        test_data = array.array("B", pattern)
        data_view = memoryview(test_data)

        # Test patterns that will have multiple matches
        test_patterns = ["48 8B 45", "45 F8 48", "89 45 E8"]

        print("\n" + "=" * 70)
        print("🎯 SIMD SPEEDUP DEMONSTRATION")
        print("=" * 70)
        print(f"   Data Size: {len(test_data)} bytes")
        print(f"   Patterns: {test_patterns}")
        print()

        # Benchmark SIMD (Cython) performance
        iterations = 20
        simd_times = []

        for _ in range(iterations):
            start_time = time.perf_counter()
            for pattern in test_patterns:
                sig = sigmaker._SimdSignature(pattern)
                result = sigmaker._simd_scan_bytes(data_view, sig)
                # Process result to ensure we're doing work
                if isinstance(result, list):
                    _ = len(result)
                elif result != -1:
                    _ = 1
            end_time = time.perf_counter()
            simd_times.append(end_time - start_time)

        # Benchmark Python fallback (what would happen without SIMD)
        python_times = []
        for _ in range(iterations):
            start_time = time.perf_counter()
            for pattern in test_patterns:
                pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
                count = 0
                for i in range(len(test_data) - len(pattern_bytes) + 1):
                    if test_data[i : i + len(pattern_bytes)] == pattern_bytes:
                        count += 1
                        if count >= 10:  # Limit to avoid excessive work
                            break
            end_time = time.perf_counter()
            python_times.append(end_time - start_time)

        # Calculate statistics
        simd_avg = sum(simd_times) / len(simd_times)
        python_avg = sum(python_times) / len(python_times)
        speedup = python_avg / simd_avg

        print("🚀 SIMD (Cython) Results:")
        print(f"   Average Time: {simd_avg:.6f}s")
        print(f"   Min Time: {min(simd_times):.6f}s")
        print(f"   Max Time: {max(simd_times):.6f}s")
        print()
        print("🐍 Python Fallback Results:")
        print(f"   Average Time: {python_avg:.6f}s")
        print(f"   Min Time: {min(python_times):.6f}s")
        print(f"   Max Time: {max(python_times):.6f}s")
        print()
        print("📊 PERFORMANCE COMPARISON:")
        print(f"   SIMD is {speedup:.1f}x faster than Python")
        print(f"   Speedup Factor: {speedup:.1f}x")
        # Assertions to verify SIMD is actually faster
        self.assertLess(
            simd_avg,
            python_avg,
            "SIMD implementation should be faster than Python fallback",
        )
        self.assertGreater(
            speedup, 1.5, "Should achieve at least 1.5x speedup with SIMD"
        )

        print("\n" + "=" * 70)
        print("✅ SIMD optimization successfully demonstrated!")
        print("=" * 70)


def main():
    """Demonstrate the Cython vs Python performance difference."""
    print("\n" + "=" * 80)
    print("🎯 CYTHON vs PYTHON PERFORMANCE DEMONSTRATION")
    print("=" * 80)

    if not sigmaker.SIMD_SPEEDUP_AVAILABLE:
        print("❌ SIMD speedup not available on this system")
        return

    # Create test data - larger for more dramatic difference
    pattern = [0x48, 0x8B, 0x45, 0xF8, 0x48, 0x89, 0x45, 0xE8] * 2000
    test_data = array.array("B", pattern)
    data_view = memoryview(test_data)

    test_patterns = ["48 8B 45", "45 F8 48", "89 45 E8"]
    iterations = 25

    print(f"📊 Test Setup:")
    print(f"   Data Size: {len(test_data)} bytes")
    print(f"   Patterns: {test_patterns}")
    print(f"   Iterations: {iterations}")
    print()

    # Benchmark SIMD (Cython)
    print("🚀 Testing SIMD (Cython) performance...")
    simd_times = []
    for i in range(iterations):
        start_time = time.perf_counter()
        for pattern in test_patterns:
            sig = sigmaker._SimdSignature(pattern)
            sigmaker._simd_scan_bytes(data_view, sig)
        end_time = time.perf_counter()
        simd_times.append(end_time - start_time)
        if (i + 1) % 10 == 0:
            print(f"   Iteration {i+1}: {sum(simd_times[-10:])/10:.8f}s avg")

    # Benchmark Python
    print("\n🐍 Testing Python performance...")
    python_times = []
    for i in range(iterations):
        start_time = time.perf_counter()
        for pattern in test_patterns:
            pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
            for j in range(len(test_data) - len(pattern_bytes) + 1):
                if test_data[j : j + len(pattern_bytes)] == pattern_bytes:
                    break
        end_time = time.perf_counter()
        python_times.append(end_time - start_time)
        if (i + 1) % 10 == 0:
            print(f"   Iteration {i+1}: {sum(python_times[-10:])/10:.8f}s avg")

    # Calculate results
    simd_avg = sum(simd_times) / len(simd_times)
    python_avg = sum(python_times) / len(python_times)
    speedup = python_avg / simd_avg

    print("\n" + "=" * 60)
    print("🏆 FINAL RESULTS")
    print("=" * 60)
    print("🚀 SIMD (Cython) Performance:")
    print(f"   Average Time: {simd_avg:.6f}s")
    print(f"   Min Time: {min(simd_times):.6f}s")
    print(f"   Max Time: {max(simd_times):.6f}s")
    print()
    print("🐍 Python Performance:")
    print(f"   Average Time: {python_avg:.6f}s")
    print(f"   Min Time: {min(python_times):.6f}s")
    print(f"   Max Time: {max(python_times):.6f}s")
    print()
    print("🎯 PERFORMANCE COMPARISON:")
    print(f"   SIMD is {speedup:.1f}x faster")
    print(f"   Speedup Factor: {speedup:.1f}x")
    print(f"   Performance Ratio: {speedup:.3f}x")
    print()
    if speedup > 100:
        print("🚀🚀🚀 INCREDIBLE PERFORMANCE GAIN! 🚀🚀🚀")
    elif speedup > 10:
        print("🚀🚀 EXCELLENT PERFORMANCE GAIN! 🚀🚀")
    elif speedup > 5:
        print("🚀 GOOD PERFORMANCE GAIN! 🚀")
    else:
        print("⚡ Moderate performance improvement")

    print("\n" + "=" * 80)
    print("✅ Cython SIMD optimization successfully demonstrated!")
    print("=" * 80)


if __name__ == "__main__":

    unittest.main()
