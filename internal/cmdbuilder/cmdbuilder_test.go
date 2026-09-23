package cmdbuilder

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCmdBuilder(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CmdBuilder Suite")
}

var _ = Describe("CmdBuilder", func() {

	Describe("Args and MaskedArgs", func() {
		It("Add appends all tokens", func() {
			Expect(New().Add("-v", "-x").Args()).To(Equal([]string{"-v", "-x"}))
		})

		It("Flag appends flag and value pair", func() {
			Expect(New().Flag("-i", "libvirt").Args()).To(Equal([]string{"-i", "libvirt"}))
		})

		Context("AddIf", func() {
			It("appends when condition is true", func() {
				Expect(New().AddIf(true, "--verbose").Args()).To(Equal([]string{"--verbose"}))
			})

			It("skips when condition is false", func() {
				Expect(New().AddIf(false, "--verbose").Args()).To(BeEmpty())
			})
		})

		Context("FlagIf", func() {
			It("appends flag and value when condition is true", func() {
				Expect(New().FlagIf(true, "-o", "val").Args()).To(Equal([]string{"-o", "val"}))
			})

			It("skips when condition is false", func() {
				Expect(New().FlagIf(false, "-o", "val").Args()).To(BeEmpty())
			})
		})

		Context("SensitiveFlag", func() {
			var b *CmdBuilder

			BeforeEach(func() {
				b = New().SensitiveFlag("--token", "secret")
			})

			It("exposes the real value in Args", func() {
				Expect(b.Args()).To(Equal([]string{"--token", "secret"}))
			})

			It("masks the value in MaskedArgs", func() {
				Expect(b.MaskedArgs()).To(Equal([]string{"--token", "***"}))
			})
		})

		Context("SensitiveArg", func() {
			var b *CmdBuilder

			BeforeEach(func() {
				b = New().SensitiveArg("password=+/tmp/f", "password=+***")
			})

			It("exposes the real token in Args", func() {
				Expect(b.Args()).To(Equal([]string{"password=+/tmp/f"}))
			})

			It("uses the display string in MaskedArgs", func() {
				Expect(b.MaskedArgs()).To(Equal([]string{"password=+***"}))
			})

			It("falls back to *** when no display string is set", func() {
				raw := &CmdBuilder{}
				raw.entries = append(raw.entries, entry{tokens: []string{"secret"}, masked: true})
				Expect(raw.MaskedArgs()).To(Equal([]string{"***"}))
			})
		})

		It("MaskedArgs handles a mix of plain and sensitive args", func() {
			b := New().
				Add("-v").
				Flag("-i", "libvirt").
				SensitiveFlag("--token", "secret").
				SensitiveArg("password=+/tmp/f", "password=+***")

			Expect(b.MaskedArgs()).To(Equal([]string{
				"-v", "-i", "libvirt", "--token", "***", "password=+***",
			}))
		})
	})

	Describe("Environment operations", func() {
		Context("SetEnv", func() {
			It("injects a variable into the built environment", func() {
				const key = "CMDBUILDER_TEST_SET"
				Expect(os.Unsetenv(key)).To(Succeed())

				env := New().SetEnv(key, "hello").buildEnv()
				Expect(env).To(ContainElement(key + "=hello"))
			})
		})

		Context("UnsetEnv", func() {
			It("removes a variable from the built environment", func() {
				const key = "CMDBUILDER_TEST_UNSET"
				DeferCleanup(os.Unsetenv, key)
				Expect(os.Setenv(key, "present")).To(Succeed())

				env := New().UnsetEnv(key).buildEnv()
				Expect(env).NotTo(ContainElement(HavePrefix(key + "=")))
			})
		})

		Context("FilterEnv", func() {
			It("transforms the variable value", func() {
				const key = "CMDBUILDER_TEST_FILTER"
				DeferCleanup(os.Unsetenv, key)
				Expect(os.Setenv(key, "a:b:c")).To(Succeed())

				env := New().FilterEnv(key, func(val string) string {
					var kept []string
					for _, p := range strings.Split(val, ":") {
						if p != "b" {
							kept = append(kept, p)
						}
					}
					return strings.Join(kept, ":")
				}).buildEnv()

				Expect(env).To(ContainElement(key + "=a:c"))
			})

			It("removes the variable when fn returns an empty string", func() {
				const key = "CMDBUILDER_TEST_FILTER_REMOVE"
				DeferCleanup(os.Unsetenv, key)
				Expect(os.Setenv(key, "remove-me")).To(Succeed())

				env := New().FilterEnv(key, func(_ string) string { return "" }).buildEnv()
				Expect(env).NotTo(ContainElement(HavePrefix(key + "=")))
			})

			It("does not call fn for absent keys", func() {
				const key = "CMDBUILDER_TEST_FILTER_ABSENT"
				Expect(os.Unsetenv(key)).To(Succeed())

				called := false
				New().FilterEnv(key, func(v string) string {
					called = true
					return v
				}).buildEnv()

				Expect(called).To(BeFalse())
			})
		})
	})

	Describe("Command", func() {
		It("passes builder args to the command", func() {
			cmd := New().Add("-v").Flag("-o", "out").Command(context.Background(), "echo")
			Expect(cmd.Args[1:]).To(Equal([]string{"-v", "-o", "out"}))
		})

		It("sets Env when env ops are registered", func() {
			const key = "CMDBUILDER_TEST_CMD_ENV"
			Expect(os.Unsetenv(key)).To(Succeed())

			cmd := New().SetEnv(key, "injected").Command(context.Background(), "echo")
			Expect(cmd.Env).To(ContainElement(key + "=injected"))
		})

		It("leaves Env nil when no env ops are registered", func() {
			Expect(New().Command(context.Background(), "echo").Env).To(BeNil())
		})
	})

	Describe("RunSeparate", func() {
		It("captures stdout and leaves stderr empty", func() {
			stdout, stderr, err := New().Add("hello").RunSeparate(context.Background(), "echo")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(stdout)).To(ContainSubstring("hello"))
			Expect(stderr).To(BeEmpty())
		})

		It("returns context.Canceled when context is cancelled", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, _, err := New().Add("-c", "sleep 10").RunSeparate(ctx, "sh")
			Expect(err).To(MatchError(context.Canceled))
		})
	})

	Describe("RunCombined", func() {
		It("captures combined output", func() {
			output, err := New().Add("-c", "echo combined").RunCombined(context.Background(), "sh")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("combined"))
		})

		It("returns an error when context is cancelled", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := New().Add("-c", "sleep 10").RunCombined(ctx, "sh")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("RunStreamed", func() {
		It("does not hang when a child inherits the output pipe", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			DeferCleanup(cancel)

			started := time.Now()
			_, err := New().Add("-c", "sleep 10 &").RunStreamed(ctx, "sh", nil)

			Expect(err).To(HaveOccurred())
			Expect(time.Since(started)).To(BeNumerically("<", 2*time.Second))
		})

		It("does not deadlock when a line exceeds the scanner limit", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			DeferCleanup(cancel)

			_, err := New().Add("-c", "head -c 2097152 /dev/zero").RunStreamed(ctx, "sh", nil)

			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, context.DeadlineExceeded)).To(BeFalse())
		})

		It("captures combined output identical to RunCombined", func() {
			output, err := New().Add("-c", "echo one; echo two >&2; echo three").
				RunStreamed(context.Background(), "sh", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("one"))
			Expect(string(output)).To(ContainSubstring("two"))
			Expect(string(output)).To(ContainSubstring("three"))
		})

		It("invokes onLine for each line as it arrives, in order", func() {
			var lines []string
			_, err := New().Add("-c", "echo alpha; echo beta; echo gamma").
				RunStreamed(context.Background(), "sh", func(line string) {
					lines = append(lines, line)
				})
			Expect(err).NotTo(HaveOccurred())
			Expect(lines).To(Equal([]string{"alpha", "beta", "gamma"}))
		})

		It("works with a nil onLine callback", func() {
			output, err := New().Add("-c", "echo quiet").
				RunStreamed(context.Background(), "sh", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("quiet"))
		})

		It("returns an error when context is cancelled", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := New().Add("-c", "sleep 10").RunStreamed(ctx, "sh", nil)
			Expect(err).To(HaveOccurred())
		})

		It("propagates a non-zero exit code via ExitCode", func() {
			_, err := New().RunStreamed(context.Background(), "false", nil)
			Expect(err).To(HaveOccurred())
			Expect(ExitCode(err)).To(Equal(1))
		})
	})

	Describe("RunStreamedSeparate", func() {
		It("captures stdout and stderr independently", func() {
			stdout, stderr, err := New().Add("-c", "echo out; echo err >&2").
				RunStreamedSeparate(context.Background(), "sh", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(stdout)).To(ContainSubstring("out"))
			Expect(string(stderr)).To(ContainSubstring("err"))
			Expect(string(stdout)).NotTo(ContainSubstring("err"))
			Expect(string(stderr)).NotTo(ContainSubstring("out"))
		})

		It("invokes onLine for each stderr line", func() {
			var lines []string
			_, _, err := New().Add("-c", "echo out; echo alpha >&2; echo beta >&2").
				RunStreamedSeparate(context.Background(), "sh", func(line string) {
					lines = append(lines, line)
				})
			Expect(err).NotTo(HaveOccurred())
			Expect(lines).To(ContainElement("alpha"))
			Expect(lines).To(ContainElement("beta"))
			Expect(lines).NotTo(ContainElement("out"))
		})

		It("works with a nil onLine callback", func() {
			stdout, stderr, err := New().Add("-c", "echo quiet; echo noise >&2").
				RunStreamedSeparate(context.Background(), "sh", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(stdout)).To(ContainSubstring("quiet"))
			Expect(string(stderr)).To(ContainSubstring("noise"))
		})

		It("returns an error and stderr when command fails", func() {
			_, stderr, err := New().Add("-c", "echo fail-info >&2; exit 1").
				RunStreamedSeparate(context.Background(), "sh", nil)
			Expect(err).To(HaveOccurred())
			Expect(ExitCode(err)).To(Equal(1))
			Expect(string(stderr)).To(ContainSubstring("fail-info"))
		})

		It("returns context.Canceled when context is cancelled", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, _, err := New().Add("-c", "sleep 10").RunStreamedSeparate(ctx, "sh", nil)
			Expect(err).To(MatchError(context.Canceled))
		})
	})

	Describe("ExitCode", func() {
		It("extracts the exit code from a failed command", func() {
			_, err := New().RunCombined(context.Background(), "false")
			Expect(err).To(HaveOccurred())
			Expect(ExitCode(err)).To(Equal(1))
		})

		It("returns -1 for a nil error", func() {
			Expect(ExitCode(nil)).To(Equal(-1))
		})
	})
})
