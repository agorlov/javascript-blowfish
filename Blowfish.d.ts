/**
 * @class Blowfish
 * @description
 * Шифратор/дешифратор. Алгоритм Blowfish
 *
 * в режиме ecb: исходная строка разбивается на 8-байтные блоки, каждый блок
 *   шифруется. Если размер блока менее 8 байт, то дополняем его до 8 байт нулями.
 * в режиме cbc: первый блок открытого текста, из 8 байт, перед шифрованием побитово
 *   складывается по модулю 2 (операция XOR) с вектором инициализации;
 *   последующие блоки открытого текста побитового складываются (XOR) с предыдущим результатом
 *   шифрования после этого зашифровываются.
 *
 * Подробнее о режимах шифрования:
 * http:// ru.wikipedia.org/wiki/%D0%A0%D0%B5%D0%B6%D0%B8%D0%BC_%D1%88%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F
 *
 * @example
 * // Пример 1: режим ECB, по умолчанию
 * var bf = new Blowfish("secret key");
 * var encrypted = bf.encrypt("конфиденциальное сообщение");
 * var decrypted = bf.decrypt(encrypted);
 *
 * // Пример 2: режим CBC (лучше подходит для шифрования длинных сообщений, более 1kb):
 * var bf = new Blowfish("key", "cbc");
 * var encrypted = bf.encrypt("secret message", "cbcvecto");
 * var decrypted = bf.decrypt(encrypted, "cbcvecto");
 *
 * // В режиме CBC вектор иницаилазиации iv это дополнительный пароль.
 *
 * // Пример 3:
 * // После шифрования получается бинарная строка. Чтобы передать
 * // зашифрованное сообщение в эл.письме нужно закодировать бинарную
 * // строку в base64
 * var bf = new Blowfish("key");
 *
 * // Для удобства включил, в этот класс методы base64Encode и base64Decode
 *
 * // Шифрование
 * var encrypted = bf.base64Encode(bf.encrypt("secret message"));
 *
 * // Расшифрование
 * var encrypted = bf.base64Decode(encrypted);
 * var decrypted = bf.decrypt(encrypted);
 *
 * @param {string} key    пароль (может быть длинной до 56 байт)
 * @param {string} [mode] режим шифрования
 * @author Alexandr Gorlov <a.gorlov@gmail.com>
 */
export declare class Blowfish {

	/**
	 *
	 * @param key
	 * @param mode?
	 */
	constructor(key: string, mode?: "ecb" | "cbc");

	/**
	 * @static
	 * @type {Array}
	 */
	public sBox0: Array<number>;

	/**
	 * @static
	 * @type {Array}
	 */
	public sBox1: Array<number>;

	/**
	 * @static
	 * @type {Array}
	 */
	public sBox2: Array<number>;

	/**
	 * @static
	 * @type {Array}
	 */
	public sBox3: Array<number>;

	/**
	 * @static
	 * @type {Array}
	 */
	public pArray: Array<number>;

	/**
	 * Пароль
	 * @type {string}
	 */
	public key: string;

	/**
	 * Режим шифрования: ecb|cbc; по умолчанию: ecb
	 * @type {string}
	 */
	public mode: string;

	/**
	 * Вектор инициализации для режима cbc
	 * @type {string}
	 */
	public iv: string;

	/**
	 * Набор символов для base64
	 * @type {string}
	 */
	public keyStr: string;

	/**
	 * Шифрует строку
	 * @param {string} string шифруемая строка
	 * @param {string} iv произвольная 8байтная строка - вектор инициализации;
	 *                    используется только в режиме CBC
	 * @throws {Error} кидает исключение при неизвестном режиме шифрования
	 * @return {string} зашифрованная строка
	 * @param string
	 * @param iv
	 * @return
	 */
	public encrypt(string: string, iv?: string): string;

	/**
	 * Расшифровывает строку
	 * @param {string} string зашифрованная строка
	 * @param {string} iv произвольная 8байтная строка - вектор инициализации
	 *                    (должен быть тотже, что и при шифровании) используется
	 *                    только в режиме CBC
	 * @throws {Error} кидает исключение при неизвестном режиме шифрования
	 * @return {string} расшифрованная строка
	 * @param string
	 * @param iv
	 * @return
	 */
	public decrypt(string: string, iv?: string): string;

	/**
	 * Шифрует в режиме ECB
	 * (приватный метод)
	 * @param {string} string шифруемая строка
	 * @return {string} зашифрованная строка
	 * @param string
	 * @return
	 */
	public encryptECB(string: string): string;

	/**
	 * Шифрует в режиме CBC
	 * (приватный метод)
	 * @param {string} string шифруемая строка
	 * @param {string} iv 8-байтная строка - вектор инициализации
	 * @return {string} зашифрованная строка
	 * @param string
	 * @param iv
	 * @return
	 */
	public encryptCBC(string: string, iv: string): string;

	/**
	 * Расшифровать в режиме ECB
	 * (приватный метод)
	 * @param {string} string шифруемая строка
	 * @throws {Error} кидает исключение если зашифрованная строка повреждена
	 * @return {string} зашифрованная строка
	 * @param string
	 * @return
	 */
	public decryptECB(string: string): string;

	/**
	 * Шифрует в режиме CBC
	 * (приватный метод)
	 * @param {string} string зашифрованная строка
	 * @param {string} iv 8-байтная строка - вектор инициализации
	 * @throws {Error} кидает исключение если зашифрованная строка повреждена
	 * @return {string} расшифрованая строка
	 * @param string
	 * @param iv
	 * @return
	 */
	public decryptCBC(string: string, iv: string): string;

	/**
	 * Функция F
	 * Function F looks like this:
	 * Divide xL into four eight-bit quarters: a, b, c, and d.
	 * Then, F(xL) = ((S1,a + S2,b mod 232) XOR S3,c) + S4,d mod 232.
	 * F(0xFFFFFF)
	 * ((S1[255] + S2[255]) XOR S3[255]) + S4[255]
	 * ((0x6e85076a + 0xdb83adf7) ^ 0x406000e0) + 0x3ac372e6
	 * @param {int32} xL 32битное значение
	 */
	public F(xL: number): number;


	/**
	 * Шифрует строку из 8 байт (один блок)
	 * Encryption and Decryption:
	 * Blowfish has 16 rounds. The input is a 64-bit data element, x.
	 * Divide x into two 32-bit halves: xL, xR. Then, for i = 1 to 16:
	 * xL = xL XOR Pi
	 * xR = F(xL) XOR xR
	 * Swap xL and xR
	 * After the sixteenth round, swap xL and xR again to undo the last swap.
	 * Then, xR = xR XOR P17 and xL = xL XOR P18. Finally, recombine xL and xR
	 * to get the ciphertext.
	 * Function F looks like this:
	 * Divide xL into four eight-bit quarters: a, b, c, and d.
	 * Then, F(xL) = ((S1,a + S2,b mod 232) XOR S3,c) + S4,d mod 232.
	 * Decryption is exactly the same as encryption, except that P1, P2,..., P18
	 * are used in the reverse order.
	 * @param {int32} xL первые 4 символа в виде числа 32битного беззнакового
	 * @param {int32} xR оставшиеся 4 символа в виде числа 32битного беззнакового
	 * @return {Array} зашифрованный 8-байтный блок в виде пары 32битных чисел [xL, xR]
	 * @param xL
	 * @param xR
	 * @return
	 */
	public encipher(xL: number, xR: number): [ number, number ];

	/**
	 * ??
	 * @param {int32} xL
	 * @param {int32} xR
	 * @return {Array}
	 * @param xL
	 * @param xR
	 * @return
	 */
	public decipher(xL: number, xR: number): [ number, number ];

	/**
	 * Генерация ключей (subkeys)
	 * Generating the Subkeys:
	 * The subkeys are calculated using the Blowfish algorithm:
	 * 1. Initialize first the P-array and then the four S-boxes, in order,
	 *    with a fixed string. This string consists of the hexadecimal digits
	 *    of pi (less the initial 3): P1 = 0x243f6a88, P2 = 0x85a308d3,
	 *    P3 = 0x13198a2e, P4 = 0x03707344, etc.
	 * 2. XOR P1 with the first 32 bits of the key, XOR P2 with the second 32-bits
	 *    of the key, and so on for all bits of the key (possibly up to P14).
	 *    Repeatedly cycle through the key bits until the entire P-array has
	 *    been XORed with key bits. (For every short key, there is at least one
	 *    equivalent longer key; for example, if A is a 64-bit key, then AA,
	 *    AAA, etc., are equivalent keys.)
	 * 3. Encrypt the all-zero string with the Blowfish algorithm, using the
	 *    subkeys described in steps (1) and (2).
	 * 4. Replace P1 and P2 with the output of step (3).
	 * 5. Encrypt the output of step (3) using the Blowfish algorithm with the
	 *    modified subkeys.
	 * 6. Replace P3 and P4 with the output of step (5).
	 * 7. Continue the process, replacing all entries of the P array, and then all
	 *    four S-boxes in order, with the output of the continuously changing
	 *    Blowfish algorithm.
	 * In total, 521 iterations are required to generate all required subkeys.
	 * Applications can store the subkeys rather than execute this derivation
	 * process multiple times.
	 *
	 * Долго пытался понять правильную последовательность генерации ключей,
	 * в итоге посмотрел как сделано в PHP реализации Crypt_Blowfish (PEAR)
	 * и разобрался.
	 * @param {string} key ключ
	 * @param key
	 */
	public generateSubkeys(key: string): number;

	/**
	 * Преобразует 4х байтную строку, в 32битное целое число
	 * @param {string} block32
	 * @return {int}
	 * @param block32
	 * @return
	 */
	public block32toNum(block32: string): number;

	/**
	 * Преобразует 32битное число в строку (4 байта)
	 * @param {int} num 32 битное число
	 * @return {string} 4х-байтная строка
	 * @param num
	 * @return
	 */
	public num2block32(num: number): string;

	/**
	 * Операция XOR
	 * @param {int} a
	 * @param {int} b
	 * @return {int}
	 * @param a
	 * @param b
	 * @return
	 */
	public xor(a: number, b: number): number;

	/**
	 * Сложение по модулю 2^32
	 * Складываем 2 числа и отрбрасываем все разряды больше 32
	 * @param {int} a
	 * @param {int} b
	 * @return {int}
	 * @param a
	 * @param b
	 * @return
	 */
	public addMod32(a: number, b: number): number;

	/**
	 * Преобразование signed int в unsigned int
	 * после побитовых операций javascript возвращает знаковое число
	 * However, for octet-data processing (eg, network stream, etc), usually
	 * want the "unsigned int" representation. This can be accomplished by
	 * adding a ">>> 0" (zero-fill right-shift) operator which internally tells
	 * Javascript to treat this as unsigned.
	 * @param {int} number целое число со знаком
	 * @return {int} целое число без знака
	 * @param number
	 * @return
	 */
	public fixNegative(number: number): number;

	/**
	 * Разделим 64 битный блок на два 32-битных
	 * @param {string} block64 блок, состоящий из 64 бит (8 байт)
	 * @return {Array} [xL, xR]
	 * @param block64
	 * @return
	 */
	public split64by32(block64: string): any[];

	/**
	 * Преобразует строку в последовательность байтов utf8
	 * на один символ может приходится больше одного байта
	 * Взял этот метод из библиотеки base64:
	 * http:// www.webtoolkit.info/javascript-base64.html
	 * @param string
	 * @return
	 */
	public utf8Decode(string: string): string;

	/**
	 * Преобразует байтовую-строку utf8 в строку javascript
	 * @param utftext
	 * @return
	 */
	public utf8Encode(utftext: string): string;

	/**
	 * Кодирует строку в base64
	 * @param {string} input
	 * @return {string}
	 * @param input
	 * @return
	 */
	public base64Encode(input: string): string;

	/**
	 * Раскодирует строку из base64
	 * @param {string} input
	 * @return {string}
	 * @param input
	 * @return
	 */
	public base64Decode(input: string): string;

	/**
	 * Удаляет символы \0 в конце строки
	 * @param {string} input
	 * @return {string}
	 * @param input
	 * @return
	 */
	public trimZeros(input: string): string;
}
