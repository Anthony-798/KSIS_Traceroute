using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

class Program {
    static void Main() {
        while (true) {  // Бесконечный цикл для ввода команд
            Console.Write("Введите команду: ");
            string input = Console.ReadLine();  // Считываем введенную команду

            if (string.IsNullOrWhiteSpace(input)) continue;  // Если строка пустая — пропускаем итерацию

            // Разбиваем строку на слова (разделитель — пробел), удаляем лишние пробелы
            string[] parts = input.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

            // Проверяем, что команда состоит из 2 частей и начинается с "tracert"
            if (parts.Length != 2 || parts[0].ToLower() != "tracert") {
                Console.WriteLine("Ошибка: используйте команду в формате tracert <IP>\n");
                continue;
            }

            string targetHost = parts[1];  // Вторая часть — это IP-адрес или доменное имя
            Traceroute(targetHost);  // Запускаем трассировку

            Console.WriteLine("\nТрассировка завершена.\n");
        }
    }

    static void Traceroute(string targetHost) {
        IPAddress targetAddress;  // Переменная для хранения целевого IP-адреса
        string resolvedHostName = targetHost;  // По умолчанию используем введенное значение

        try {
            // Преобразуем имя хоста в IP-адрес (если ввели имя, например "google.com")
            IPAddress[] addresses = Dns.GetHostAddresses(targetHost);
            targetAddress = addresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork) ?? addresses.First();

            // Пытаемся получить имя хоста по IP (обратное разрешение)
            string reverseHost = GetHostName(targetAddress);
            if (reverseHost != "Неизвестный хост" && reverseHost != targetHost) {
                resolvedHostName = reverseHost;  // Если нашли имя хоста, используем его
            }
        }
        catch (Exception ex) {
            Console.WriteLine($"Ошибка при разрешении хоста: {ex.Message}");
            return;
        }

        // Выводим заголовок трассировки
        Console.WriteLine($"\nТрассировка маршрута к {resolvedHostName} [{targetAddress}]");
        Console.WriteLine("с максимальным числом прыжков 30:\n");

        using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp)) {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 3000);  // Таймаут на получение ответа 3 сек

            int sequenceNumber = 1; // Начальное значение Sequence Number

            for (int ttl = 1; ttl <= 30; ttl++) {  // Цикл с TTL от 1 до 30 (макс. число прыжков)
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, ttl);  // Устанавливаем TTL
                EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);  // Адрес для получения ответа

                long[] times = new long[3];  // Массив для хранения трех измерений времени
                IPAddress hopAddress = null;  // IP-адрес текущего узла

                for (int i = 0; i < 3; i++) {  // Отправляем по 3 запроса на каждом узле
                    byte[] icmpPacket = CreateIcmpPacket((ushort)sequenceNumber);  // Передаем увеличивающийся Sequence Number
                    sequenceNumber++; // Увеличиваем номер после каждой отправки

                    Stopwatch stopwatch = new Stopwatch();  // Засекаем время
                    try {
                        socket.SendTo(icmpPacket, new IPEndPoint(targetAddress, 0));  // Отправляем ICMP-запрос
                        stopwatch.Start();

                        byte[] buffer = new byte[1024];
                        int bytesReceived = socket.ReceiveFrom(buffer, ref remoteEndPoint);  // Ждем ответ
                        stopwatch.Stop();

                        times[i] = stopwatch.ElapsedMilliseconds;  // Записываем время ответа
                        hopAddress = ((IPEndPoint)remoteEndPoint).Address;  // Получаем IP-адрес узла
                    }
                    catch (SocketException) {
                        times[i] = -1;  // Если таймаут, записываем -1
                    }
                    Thread.Sleep(100);  // Задержка перед следующим запросом
                }

                PrintTracerouteLine(ttl, times, hopAddress);  // Выводим результаты

                if (hopAddress != null && hopAddress.Equals(targetAddress))  // Если дошли до цели — выходим
                    break;
            }
        }
    }

    static void PrintTracerouteLine(int ttl, long[] times, IPAddress hopAddress) {
        string time1 = times[0] >= 0 ? $"{times[0]} ms" : "*";
        string time2 = times[1] >= 0 ? $"{times[1]} ms" : "*";
        string time3 = times[2] >= 0 ? $"{times[2]} ms" : "*";

        if (hopAddress == null) {  // Если узел не ответил
            Console.WriteLine($"{ttl,3}   {time1,5}   {time2,5}   {time3,5}   Превышен интервал ожидания для запроса.");
        }
        else {
            string hostname = GetHostName(hopAddress);  // Получаем имя хоста
            if (hostname == null || hostname == hopAddress.ToString()) {
                Console.WriteLine($"{ttl,3}   {time1,5}   {time2,5}   {time3,5}   {hopAddress}");  // Выводим только IP
            }
            else {
                Console.WriteLine($"{ttl,3}   {time1,5}   {time2,5}   {time3,5}   {hostname} [{hopAddress}]");  // Выводим имя + IP
            }
        }
    }

    static string GetHostName(IPAddress ip) {
        try {
            return Dns.GetHostEntry(ip).HostName;  // Получаем имя хоста
        }
        catch {
            return ip.ToString();  // Если не получилось, возвращаем просто IP
        }
    }
 
    static byte[] CreateIcmpPacket(ushort sequenceNumber) {
        byte[] data = new byte[64];  // 64 байта данных (как в системном tracert)
        Array.Clear(data, 0, data.Length); // Заполняем нулями

        byte[] packet = new byte[8 + data.Length];  // 8 байт ICMP заголовка + 64 байта данных (итого 72 байта)

        packet[0] = 8; // Тип: Echo Request
        packet[1] = 0; // Код: 0
        Array.Copy(BitConverter.GetBytes((ushort)0), 0, packet, 2, 2); // Контрольная сумма (пока 0)

        // Identifier (1 в Big-Endian)
        ushort identifier = 1;
        Array.Copy(BitConverter.GetBytes((ushort)((identifier << 8) | (identifier >> 8))), 0, packet, 4, 2);

        // Sequence Number (Big-Endian)
        ushort sequenceNumberBE = (ushort)((sequenceNumber << 8) | (sequenceNumber >> 8));
        Array.Copy(BitConverter.GetBytes(sequenceNumberBE), 0, packet, 6, 2);

        // Копируем данные (64 байта) в начало полезной нагрузки (байт 8)
        Array.Copy(data, 0, packet, 8, data.Length);

        // Вычисляем контрольную сумму и записываем
        ushort checksum = ComputeChecksum(packet);
        Array.Copy(BitConverter.GetBytes(checksum), 0, packet, 2, 2);

        return packet;
    }


    static ushort ComputeChecksum(byte[] data) {
        int sum = 0;
        for (int i = 0; i < data.Length; i += 2) {
            sum += BitConverter.ToUInt16(data, i);  // Складываем пары байтов
        }
        while ((sum >> 16) != 0) {  // Складываем верхние и нижние 16 бит
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (ushort)~sum;  // Инвертируем результат
    }
}




