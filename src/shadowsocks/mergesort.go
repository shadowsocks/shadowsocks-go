package shadowsocks

func merge(left, right []int, comparison func (int, int) int) []int {
	result := make([]int, len(left) + len(right))
	l, r := 0, 0
	for (l < len(left)) && (r < len(right)) {
		if comparison(left[l], right[r]) <= 0 {
			result[l + r] = left[l]
			l++
		} else {
			result[l + r] = right[r]
			r++
		}
	}
	for (l < len(left)) {
		result[l + r] = left[l]
		l++
	}
	for (r < len(right)) {
		result[l + r] = right[r]
		r++
	}
	return result
}

func Sort(arr []int, comparison func (int, int) int) []int {
	if len(arr) < 2 {
		return arr
	}
	var middle int = int(len(arr)/2)
	return merge(Sort(arr[0:middle], comparison), Sort(arr[middle:], comparison), comparison)
}
