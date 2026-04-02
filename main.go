package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Результаты сканирования
type ScanResult struct {
	TargetURL     string
	Directories   []string
	XSSVulnerable []string
	OpenPorts     []int
	IsSecure      bool
	Issues        []string
}

// Сканер директорий
func scanDirectories(targetURL string, wordlist []string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, dir := range wordlist {
		url := fmt.Sprintf("%s/%s", strings.TrimRight(targetURL, "/"), dir)
		resp, err := client.Get(url)

		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				result := fmt.Sprintf("[DIR] %s (Status: %d)", url, resp.StatusCode)
				results <- result
			}
		}
		time.Sleep(50 * time.Millisecond) // Избегаем перегрузки
	}
}

// Сканер XSS
func scanXSS(targetURL string, payloads []string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, payload := range payloads {
		testURL := fmt.Sprintf("%s?q=%s", targetURL, payload)
		resp, err := client.Get(testURL)

		if err == nil {
			defer resp.Body.Close()

			// Простая проверка на отражение payload'а
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			if strings.Contains(body, payload) {
				result := fmt.Sprintf("[XSS] Потенциальная уязвимость: %s", testURL)
				results <- result
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Сканер портов
func scanPorts(target string, ports []int, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)

		if err == nil {
			conn.Close()
			result := fmt.Sprintf("[PORT] Порт %d открыт", port)
			results <- result
		}
	}
}

// Оценка безопасности
func evaluateSecurity(dirResults, xssResults, portResults []string) (bool, []string) {
	var issues []string
	isSecure := true

	if len(xssResults) > 0 {
		isSecure = false
		issues = append(issues, "Обнаружены XSS уязвимости")
	}

	if len(dirResults) > 0 {
		issues = append(issues, fmt.Sprintf("Обнаружены открытые директории (%d шт.)", len(dirResults)))
	}

	// Проверяем опасные открытые порты
	dangerousPorts := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	for _, portResult := range portResults {
		var port int
		fmt.Sscanf(portResult, "[PORT] Порт %d открыт", &port)
		if service, exists := dangerousPorts[port]; exists {
			issues = append(issues, fmt.Sprintf("Открыт опасный порт %d (%s)", port, service))
			isSecure = false
		}
	}

	return isSecure, issues
}

func main() {
	// Параметры командной строки
	target := flag.String("url", "", "Целевой URL (например, http://example.com)")
	host := flag.String("host", "", "Хост для сканирования портов (например, example.com)")
	flag.Parse()

	if *target == "" && *host == "" {
		fmt.Println("Использование: ./scanner -url <URL> -host <HOST>")
		fmt.Println("Пример: ./scanner -url http://testphp.vulnweb.com -host testphp.vulnweb.com")
		return
	}

	// Словлисты
	directories := []string{
		"admin", "login", "wp-admin", "backup", "config", "sql",
		"phpmyadmin", "uploads", "images", "css", "js", "robots.txt",
		".git", ".env", "backup.zip", "database.sql",
	}

	xssPayloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"<body onload=alert('XSS')>",
	}

	ports := []int{80, 443, 22, 21, 25, 3306, 5432, 6379, 8080, 8443, 27017}

	// Каналы для сбора результатов
	dirChan := make(chan string, 100)
	xssChan := make(chan string, 100)
	portChan := make(chan string, 100)

	var wg sync.WaitGroup

	// Запуск сканирования
	fmt.Println("=== Начало сканирования безопасности ===")
	fmt.Printf("Время: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Сканирование директорий
	if *target != "" {
		fmt.Println("[*] Запуск сканера директорий...")
		wg.Add(1)
		go scanDirectories(*target, directories, dirChan, &wg)
	}

	// Сканирование XSS
	if *target != "" {
		fmt.Println("[*] Запуск XSS сканера...")
		wg.Add(1)
		go scanXSS(*target, xssPayloads, xssChan, &wg)
	}

	// Сканирование портов
	if *host != "" {
		fmt.Println("[*] Запуск сканера портов...")
		wg.Add(1)
		go scanPorts(*host, ports, portChan, &wg)
	}

	// Закрываем каналы после завершения всех горутин
	go func() {
		wg.Wait()
		close(dirChan)
		close(xssChan)
		close(portChan)
	}()

	// Сбор результатов
	var dirResults []string
	var xssResults []string
	var portResults []string

	// Чтение результатов из каналов
	for result := range dirChan {
		dirResults = append(dirResults, result)
		fmt.Println(result)
	}

	for result := range xssChan {
		xssResults = append(xssResults, result)
		fmt.Println(result)
	}

	for result := range portChan {
		portResults = append(portResults, result)
		fmt.Println(result)
	}

	// Оценка безопасности
	fmt.Println("\n=== Анализ результатов ===")
	isSecure, issues := evaluateSecurity(dirResults, xssResults, portResults)

	if isSecure {
		fmt.Println("\n✅ Статус: СЕРВЕР ЗАЩИЩЕН")
		fmt.Println("Не обнаружено критических уязвимостей")
	} else {
		fmt.Println("\n❌ Статус: СЕРВЕР УЯЗВИМ")
		fmt.Println("Обнаруженные проблемы:")
		for i, issue := range issues {
			fmt.Printf("  %d. %s\n", i+1, issue)
		}
	}

	// Детальный отчет
	fmt.Println("\n=== ДЕТАЛЬНЫЙ ОТЧЕТ ===")
	fmt.Printf("Целевой URL: %s\n", *target)
	fmt.Printf("Хост: %s\n", *host)
	fmt.Printf("\nОбнаружено директорий: %d\n", len(dirResults))
	fmt.Printf("XSS уязвимостей: %d\n", len(xssResults))
	fmt.Printf("Открытых портов: %d\n", len(portResults))

	if len(portResults) > 0 {
		fmt.Println("\nОткрытые порты:")
		for _, port := range portResults {
			fmt.Printf("  %s\n", port)
		}
	}

	// Сохранение отчета в файл
	reportFile := fmt.Sprintf("scan_report_%d.txt", time.Now().Unix())
	file, err := os.Create(reportFile)
	if err == nil {
		defer file.Close()
		writer := bufio.NewWriter(file)

		fmt.Fprintf(writer, "=== ОТЧЕТ О СКАНИРОВАНИИ БЕЗОПАСНОСТИ ===\n")
		fmt.Fprintf(writer, "Время: %s\n", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Fprintf(writer, "Цель: %s\n", *target)
		fmt.Fprintf(writer, "Хост: %s\n\n", *host)

		fmt.Fprintf(writer, "НАЙДЕННЫЕ ДИРЕКТОРИИ:\n")
		for _, dir := range dirResults {
			fmt.Fprintf(writer, "  %s\n", dir)
		}

		fmt.Fprintf(writer, "\nXSS УЯЗВИМОСТИ:\n")
		for _, xss := range xssResults {
			fmt.Fprintf(writer, "  %s\n", xss)
		}

		fmt.Fprintf(writer, "\nОТКРЫТЫЕ ПОРТЫ:\n")
		for _, port := range portResults {
			fmt.Fprintf(writer, "  %s\n", port)
		}

		fmt.Fprintf(writer, "\nИТОГОВАЯ ОЦЕНКА:\n")
		if isSecure {
			fmt.Fprintf(writer, "Статус: ЗАЩИЩЕН\n")
		} else {
			fmt.Fprintf(writer, "Статус: УЯЗВИМ\n")
			fmt.Fprintf(writer, "Проблемы:\n")
			for _, issue := range issues {
				fmt.Fprintf(writer, "  - %s\n", issue)
			}
		}

		writer.Flush()
		fmt.Printf("\n📄 Отчет сохранен в файл: %s\n", reportFile)
	}

	fmt.Println("\n=== Сканирование завершено ===")
}
