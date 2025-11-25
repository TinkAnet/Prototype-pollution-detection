/**
 * 输入：matrix = [[1,2,3],[4,5,6],[7,8,9]]
 * 输出：[1,2,3,6,9,8,7,4,5]
 * 输入：matrix = [[1,2,3,4],[5,6,7,8],[9,10,11,12]]
 * 输出：[1,2,3,4,8,12,11,10,9,5,6,7]
 */

function spiralOrder(matrix: number[][]): number[] {
    if (matrix.length === 0) return []
    let res: number[] = []
    let row = matrix.length
    let col = matrix[0].length
    let left = 0
    let right = col - 1
    let top = 0
    let bottom = row - 1
    while (left <= right && top <= bottom) {
        for (let i = left; i <= right; i++) {
            res.push(matrix[top][i])
        }
        for (let i = top + 1; i <= bottom; i++) {
            res.push(matrix[i][right])
        }
        if (left < right && top < bottom) {
            for (let i = right - 1; i > left; i--) {
                res.push(matrix[bottom][i])
            }
            for (let i = bottom; i > top; i--) {
                res.push(matrix[i][left])
            }
        }
        left++
        right--
        top++
        bottom--
    }
    return res
}

// console.log(spiralOrder([[1, 2, 3], [4, 5, 6], [7, 8, 9]]));




/**
 * 输入: root = [1,3,2,5,3,null,9]
 * 输出: [1,3,9]
 * 输入: root = [1,2,3]
 * 输出: [1,3]
 * 二叉树每层的最大值
 */
class TreeNode {
    val: number
    left: TreeNode | null
    right: TreeNode | null
    constructor(val?: number, left?: TreeNode | null, right?: TreeNode | null) {
        this.val = (val === undefined ? 0 : val)
        this.left = (left === undefined ? null : left)
        this.right = (right === undefined ? null : right)
    }
}

function largestValues(root: TreeNode | null): number[] {
    if (!root) return []
    let res: number[] = []
    let queue: TreeNode[] = [root]
    while (queue.length) {
        let max = -Infinity
        let len = queue.length
        while (len--) {
            let node = queue.shift()!
            max = Math.max(max, node.val)
            node.left && queue.push(node.left)
            node.right && queue.push(node.right)
        }
        res.push(max)
    }
    return res
};

// console.log(largestValues(new TreeNode(1, new TreeNode(3, new TreeNode(5), new TreeNode(3)), new TreeNode(2, null, new TreeNode(9)))));


/**
 * 给你一个下标从 0 开始的整数数组 nums ，它表示英雄的能力值。如果我们选出一部分英雄，这组英雄的 力量 定义为：
i0 ，i1 ，... ik 表示这组英雄在数组中的下标。那么这组英雄的力量为 max(nums[i0],nums[i1] ... nums[ik])2 * min(nums[i0],nums[i1] ... nums[ik]) 。
请你返回所有可能的 非空 英雄组的 力量 之和。由于答案可能非常大，请你将结果对 109 + 7 取余。
 * 输入：nums = [2,1,4]
 * 输出：141
 * 输入：nums = [1,1,1]
 * 输出：7
 */

function sumOfPower(nums: number[]): number {
    nums.sort((a, b) => a - b);
    const mod = Math.pow(10, 9) + 7;
    let res = 0, prev = 0;
    for (let item of nums) {
        res = Number((BigInt(res) + BigInt(item) * BigInt(item) * BigInt(prev + item)) % BigInt(mod));
        prev = (prev * 2 + item) % mod
    }
    return res;
};

// 备份做法
function sumOfPowers(nums: number[]): number {
    const mod = 1e9 + 7;
    nums.sort((a, b) => a - b);
    let ans = 0;
    let p = 0;
    for (let i = nums.length - 1; i >= 0; --i) {
        const x = BigInt(nums[i]);
        ans = (ans + Number((x * x * x) % BigInt(mod))) % mod;
        ans = (ans + Number((x * BigInt(p)) % BigInt(mod))) % mod;
        p = Number((BigInt(p) * 2n + x * x) % BigInt(mod));
    }
    return ans;
}

// console.log(getArr([658, 489, 777, 2418, 1893, 130, 2448, 178, 1128, 2149, 1059, 1495, 1166, 608, 2006, 713, 1906, 2108, 680, 1348, 860, 1620, 146, 2447, 1895, 1083, 1465, 2351, 1359, 1187, 906, 533, 1943, 1814, 1808, 2065, 1744, 254, 1988, 1889, 1206]));
// console.log(sumOfPower([2, 1, 4]));
// 卡牌翻面
function flipgame(fronts: number[], backs: number[]): number {
    const same = new Set();
    for (let i = 0; i < fronts.length; i++) {
        if (fronts[i] === backs[i]) {
            same.add(fronts[i]);
        }
    }
    let res = 3000;
    for (let x of fronts) {
        if (x < res && !same.has(x)) {
            res = x;
        }
    }
    for (let x of backs) {
        if (x < res && !same.has(x)) {
            res = x;
        }
    }
    return res % 3000;
};

// console.log(flipgame([1, 2, 4, 4, 7], [1, 3, 4, 1, 3]));


/**
 * 给你一个整数数组 nums ，请计算数组的 中心下标 。
    *
  *  数组 中心下标 是数组的一个下标，其左侧所有元素相加的和等于右侧所有元素相加的和。
*
  *  如果中心下标位于数组最左端，那么左侧数之和视为 0 ，因为在下标的左侧不存在元素。这一点对于中心下标位于数组最右端同样适用。
*
  *  如果数组有多个中心下标，应该返回 最靠近左边 的那一个。如果数组不存在中心下标，返回 -1 。
 */

function pivotIndex(nums: number[]): number {
    let sum = nums.reduce((a, b) => a + b, 0)
    let left = 0
    for (let i = 0; i < nums.length; i++) {
        if (left === sum - left - nums[i]) return i
        left += nums[i]
    }
    return -1
}

// console.log(pivotIndex([1, 7, 3, 6, 5, 6]));



/**
 * 给你两个按 非递减顺序 排列的整数数组 nums1 和 nums2，另有两个整数 m 和 n ，分别表示 nums1 和 nums2 中的元素数目。

请你 合并 nums2 到 nums1 中，使合并后的数组同样按 非递减顺序 排列。

注意：最终，合并后数组不应由函数返回，而是存储在数组 nums1 中。为了应对这种情况，nums1 的初始长度为 m + n，其中前 m 个元素表示应合并的元素，后 n 个元素为 0 ，应忽略。nums2 的长度为 n 。
 */

function merge(nums1: number[], m: number, nums2: number[], n: number): number[] {
    if (m === 0) {
        return nums2
    }
    if (n === 0) {
        return nums1
    }
    for (let i = nums1.length - 1; i >= 0; i--) {
        for (let j = nums2.length - 1; j >= 0; j--) {
            if (nums1[i] === 0) {
                nums1[i] = nums2[j]
                nums2.splice(j, 1)
                break
            }
            if (nums1[i] !== 0) {
                nums1[i] = nums1[i]
                break
            }

        }
    }
    return nums1.sort((a, b) => a - b)
}

// console.log(merge([0, 0, 3, 0, 0, 0, 4, 2, 0], 3, [-1, 1, 1, 1, 2, 3], 6));


/**
 * 
 * 给你 k 枚相同的鸡蛋，并可以使用一栋从第 1 层到第 n 层共有 n 层楼的建筑。

已知存在楼层 f ，满足 0 <= f <= n ，任何从 高于 f 的楼层落下的鸡蛋都会碎，从 f 楼层或比它低的楼层落下的鸡蛋都不会破。

每次操作，你可以取一枚没有碎的鸡蛋并把它从任一楼层 x 扔下（满足 1 <= x <= n）。如果鸡蛋碎了，你就不能再次使用它。如果某枚鸡蛋扔下后没有摔碎，则可以在之后的操作中 重复使用 这枚鸡蛋。

请你计算并返回要确定 f 确切的值 的 最小操作次数 是多少？

 */

function superEggDrop(k: number, n: number): number {
    let dp = new Array(k + 1).fill(0).map(() => new Array(n + 1).fill(0))
    let m = 0
    while (dp[k][m] < n) {
        m++
        for (let i = 1; i <= k; i++) {
            dp[i][m] = dp[i][m - 1] + dp[i - 1][m - 1] + 1
        }
    }
    return m
}

// console.log(superEggDrop(3, 14));

/**
 * 给定长度为n的字符串S进行 c 次操作，每次操作将SI到S复制到字符串尾。全部操作结束后有 次询问，每次询问字符串s的第k位。
 * 1<n < 2.105,1<c< 40,1< g104.11018,1 < k< 1018
 * 数据保证r不超过当前字符串长度，k 不超过最终字符串长度。
 */


// 正确程度未知
// function getStr(s: string, c: number, r: number, k: number): string {
//     let str = s
//     while (c--) {
//         str += str.slice(0, r)
//     }
//     return str[k - 1]
// }

// console.log(getStr('abc', 2, 1, 4));




/**
 * 现给定一个函数 fn ，返回该函数的一个 记忆化 版本。

一个 记忆化 的函数是一个函数，它不会被相同的输入调用两次。而是会返回一个缓存的值。

函数 fn 可以是任何函数，对它所接受的值类型没有任何限制。如果两个输入值在 JavaScript 中使用 === 运算符比较时相等，则它们被视为相同。
 */

type Fn = (...params: any) => any

function memoize(fn: Fn): Fn {
    const argMap = new Map();
    const argsMap = new Map();
    let id: number = 0;
    return function (...args) {
        let key = ""
        for (let item of args) {
            if (!argMap.has(item)) argMap.set(item, id++);
            key += argMap.get(item) + "-";
        }
        if (argsMap.has(key)) {
            return argsMap.get(key);
        } else {
            const res = fn(...args);
            argsMap.set(key, res);
            return res;
        }
    }
}

