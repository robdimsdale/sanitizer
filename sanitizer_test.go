package sanitizer_test

import (
	"bytes"
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/robdimsdale/sanitizer"
)

var _ = Describe("Sanitizer", func() {
	var (
		tempDir     string
		writeBuffer bytes.Buffer

		pairs map[string]string
		s     sanitizer.Sanitizer
	)

	BeforeEach(func() {
		writeBuffer = bytes.Buffer{}

		var err error
		tempDir, err = ioutil.TempDir("", "santizer")
		Expect(err).NotTo(HaveOccurred())

		pairs = make(map[string]string)

		s = sanitizer.NewSanitizer(pairs, &writeBuffer)
	})

	AfterEach(func() {
		err := os.RemoveAll(tempDir)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("NewSanitizer", func() {
		Context("when a key is empty", func() {
			It("ignores the key", func() {
				pairs[""] = "***empty-redaction***"
				s = sanitizer.NewSanitizer(pairs, &writeBuffer)

				_, err := s.Write([]byte("not redacted at all"))
				Expect(err).NotTo(HaveOccurred())

				s := writeBuffer.String()
				Expect(s).To(Equal("not redacted at all"))
			})
		})
	})

	Describe("Write", func() {
		It("sanitizes correctly", func() {
			pairs["secret_value"] = "***secret-redacted***"
			pairs["super_secret_value"] = "***super-secret-redacted***"
			_, err := s.Write([]byte("my secret is: secret_value"))
			Expect(err).NotTo(HaveOccurred())

			s := writeBuffer.String()
			Expect(s).To(Equal("my secret is: ***secret-redacted***"))
		})
	})
})
