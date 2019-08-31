
#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"
#include "keyboard.h"
#include "stdlib.h"

/*****************************************************************************
*                               kernel_main
*****************************************************************************/
/**
* jmp from kernel.asm::_start.
*
*****************************************************************************/
PUBLIC int kernel_main()
{
	disp_str("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

	schedule_flag = RR_SCHEDULE;

	int i, j, eflags, prio;
	u8  rpl;
	u8  priv; /* privilege */

	struct task * t;
	struct proc * p = proc_table;

	char * stk = task_stack + STACK_SIZE_TOTAL;

	for (i = 0; i < NR_TASKS + NR_PROCS; i++, p++, t++) {
		if (i >= NR_TASKS + NR_NATIVE_PROCS) {
			p->p_flags = FREE_SLOT;
			continue;
		}

		if (i < NR_TASKS) {     /* TASK */
			t = task_table + i;
			priv = PRIVILEGE_TASK;
			rpl = RPL_TASK;
			eflags = 0x1202;/* IF=1, IOPL=1, bit 2 is always 1 */
			prio = 15;
		}
		else {                  /* USER PROC */
			t = user_proc_table + (i - NR_TASKS);
			priv = PRIVILEGE_USER;
			rpl = RPL_USER;
			eflags = 0x202;	/* IF=1, bit 2 is always 1 */
			prio = 5;
		}

		strcpy(p->name, t->name);	/* name of the process */
		p->p_parent = NO_TASK;

		if (strcmp(t->name, "INIT") != 0) {
			p->ldts[INDEX_LDT_C] = gdt[SELECTOR_KERNEL_CS >> 3];
			p->ldts[INDEX_LDT_RW] = gdt[SELECTOR_KERNEL_DS >> 3];

			/* change the DPLs */
			p->ldts[INDEX_LDT_C].attr1 = DA_C | priv << 5;
			p->ldts[INDEX_LDT_RW].attr1 = DA_DRW | priv << 5;
		}
		else {		/* INIT process */
			unsigned int k_base;
			unsigned int k_limit;
			int ret = get_kernel_map(&k_base, &k_limit);
			assert(ret == 0);
			init_desc(&p->ldts[INDEX_LDT_C],
				0, /* bytes before the entry point
				   * are useless (wasted) for the
				   * INIT process, doesn't matter
				   */
				(k_base + k_limit) >> LIMIT_4K_SHIFT,
				DA_32 | DA_LIMIT_4K | DA_C | priv << 5);

			init_desc(&p->ldts[INDEX_LDT_RW],
				0, /* bytes before the entry point
				   * are useless (wasted) for the
				   * INIT process, doesn't matter
				   */
				(k_base + k_limit) >> LIMIT_4K_SHIFT,
				DA_32 | DA_LIMIT_4K | DA_DRW | priv << 5);
		}

		p->regs.cs = INDEX_LDT_C << 3 | SA_TIL | rpl;
		p->regs.ds =
			p->regs.es =
			p->regs.fs =
			p->regs.ss = INDEX_LDT_RW << 3 | SA_TIL | rpl;
		p->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;
		p->regs.eip = (u32)t->initial_eip;
		p->regs.esp = (u32)stk;
		p->regs.eflags = eflags;

		p->ticks = p->priority = prio;

		p->p_flags = 0;
		p->p_msg = 0;
		p->p_recvfrom = NO_TASK;
		p->p_sendto = NO_TASK;
		p->has_int_msg = 0;
		p->q_sending = 0;
		p->next_sending = 0;

		for (j = 0; j < NR_FILES; j++)
			p->filp[j] = 0;

		stk -= t->stacksize;
	}

	k_reenter = 0;
	ticks = 0;

	p_proc_ready = proc_table;

	init_clock();
	init_keyboard();

	restart();

	while (1) {}
}


/*****************************************************************************
*                                get_ticks
*****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}


/**
* @struct posix_tar_header
* Borrowed from GNU `tar'
*/
struct posix_tar_header
{				/* byte offset */
	char name[100];		/*   0 */
	char mode[8];		/* 100 */
	char uid[8];		/* 108 */
	char gid[8];		/* 116 */
	char size[12];		/* 124 */
	char mtime[12];		/* 136 */
	char chksum[8];		/* 148 */
	char typeflag;		/* 156 */
	char linkname[100];	/* 157 */
	char magic[6];		/* 257 */
	char version[2];	/* 263 */
	char uname[32];		/* 265 */
	char gname[32];		/* 297 */
	char devmajor[8];	/* 329 */
	char devminor[8];	/* 337 */
	char prefix[155];	/* 345 */
						/* 500 */
};

/* Imported functions */
extern void prom_printf(char *fmt, ...);

PUBLIC snakeControl = 0;
PUBLIC chessControl = 0;


static char *malloc_ptr = 0;
static char *malloc_top = 0;
static char *last_alloc = 0;

void malloc_init(void *bottom, unsigned long size)
{
	malloc_ptr = bottom;
	malloc_top = bottom + size;
}

void malloc_dispose(void)
{
	malloc_ptr = 0;
	last_alloc = 0;
}

void *malloc(unsigned int size)
{
	char *caddr;

	if (!malloc_ptr)
		return NULL;
	if ((malloc_ptr + size + sizeof(int)) > malloc_top) {
		printf("malloc failed\n");
		return NULL;
	}
	*(int *)malloc_ptr = size;
	caddr = malloc_ptr + sizeof(int);
	malloc_ptr += size + sizeof(int);
	last_alloc = caddr;
	malloc_ptr = (char *)((((unsigned int)malloc_ptr) + 3) & (~3));
	return caddr;
}

void *realloc(void *ptr, unsigned int size)
{
	char *caddr, *oaddr = ptr;

	if (!malloc_ptr)
		return NULL;
	if (oaddr == last_alloc) {
		if (oaddr + size > malloc_top) {
			printf("realloc failed\n");
			return NULL;
		}
		*(int *)(oaddr - sizeof(int)) = size;
		malloc_ptr = oaddr + size;
		return oaddr;
	}
	caddr = malloc(size);
	if (caddr != 0 && oaddr != 0)
		memcpy(caddr, oaddr, *(int *)(oaddr - sizeof(int)));
	return caddr;
}

void free(void *m)
{
	if (!malloc_ptr)
		return;
	if (m == last_alloc)
		malloc_ptr = (char *)last_alloc - sizeof(int);
}

void mark(void **ptr)
{
	if (!malloc_ptr)
		return;
	*ptr = (void *)malloc_ptr;
}

void release(void *ptr)
{
	if (!malloc_ptr)
		return;
	malloc_ptr = (char *)ptr;
}

char *strdup(char const *str)
{
	char *p = malloc(strlen(str) + 1);
	if (p)
		strcpy(p, str);
	return p;
}
int my_atoi(const char *s)
{
	int num;
	int i;
	char ch;
	num = 0;
	for (i = 0; i < strlen(s); i++)
	{
		ch = s[i];
		//printf("In the my_atoi:%c\n",ch);
		if (ch < '0' || ch > '9')
			break;
		num = num * 10 + (ch - '0');
	}
	return num;
}
double my_atof(const char *str)
{
	double s = 0.0;

	double d = 10.0;
	int jishu = 0;

	int falg = 0;  //0为false,1为true

	while (*str == ' ')
	{
		str++;
	}

	if (*str == '-')//记录数字正负  
	{
		falg = 1;
		str++;
	}

	if (!(*str >= '0'&&*str <= '9'))//如果一开始非数字则退出，返回0.0  
		return s;

	while (*str >= '0'&&*str <= '9'&&*str != '.')//计算小数点前整数部分  
	{
		s = s*10.0 + *str - '0';
		str++;
	}

	if (*str == '.')//以后为小数部分  
		str++;

	while (*str >= '0'&&*str <= '9')//计算小数部分  
	{
		s = s + (*str - '0') / d;
		d *= 10.0;
		str++;
	}

	if (*str == 'e' || *str == 'E')//考虑科学计数法  
	{
		str++;
		if (*str == '+')
		{
			str++;
			while (*str >= '0'&&*str <= '9')
			{
				jishu = jishu * 10 + *str - '0';
				str++;
			}
			while (jishu>0)
			{
				s *= 10;
				jishu--;
			}
		}
		if (*str == '-')
		{
			str++;
			while (*str >= '0'&&*str <= '9')
			{
				jishu = jishu * 10 + *str - '0';
				str++;
			}
			while (jishu>0)
			{
				s /= 10;
				jishu--;
			}
		}
	}

	printf("DOUBLE : %f\n", s);
	return s*(falg ? -1.0 : 1.0);
}

#define clrscr() clear()
char snake_Array[17][30] =
{
	{ '=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=','=','=','=','=','=','=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=',' ',' ',' ','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','=','=','\n','\0' },
	{ '=',' ',' ','=','=','=','=','=','=','=','=','=','=','=','=','=','=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','=','=','=','=','=','=','=','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ','=',' ',' ','=','=','=',' ',' ','=','=','=','=','=','=','=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','=','=','=','=','=','=','=','=',' ','=','\n','\0' },
	{ '=','=','=','=','=',' ',' ','=','=','=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','=',' ',' ',' ',' ',' ',' ',' ','=',' ','=',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ','=','=','=','=','=','=',' ','=','=','=','=',' ',' ',' ','=','=','=','=','=','=','=','=','=','=','=','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','=','\n','\0' },
	{ '=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=','=',' ','=','=','=','=','\n','\0' } };
int snake_head[2] = { 1,2 };
int snake_area_width = 30;
int snake_area_height = 17;
int move_direction = 4;

void sleep(int pauseTime)
{
	int i = 0;
	for (i = 0; i<pauseTime * 1000000; i++)
	{
		;
	}
}
void diplaySnakeArea() {
	clear();
	int i;
	for (i = 0; i<snake_area_height; i++) {
		printf(snake_Array[i]);
	}
}


//start the game

int snake_state = 0;
void Maze() {
	while (snake_head[0] != snake_area_height - 1 && snake_head[1] != snake_area_width - 3 && snake_head[0] != 0 && snake_head[1] != 0) {
		snake_Array[snake_head[0]][snake_head[1]] = 'o';
		//up
		diplaySnakeArea();
		snake_Array[snake_head[0]][snake_head[1]] = ' ';
		if (move_direction == 1)
		{
			snake_head[0]--;
		}
		//down
		if (move_direction == 2)
		{
			snake_head[0]++;
		}
		//left
		if (move_direction == 3)
		{
			snake_head[1]--;
		}
		//right
		if (move_direction == 4)
		{
			snake_head[1]++;
		}
		if (snake_Array[snake_head[0]][snake_head[1]] == '=')
		{
			snake_state = 0;
			break;
		}
		if (snake_head[0] == 16 && snake_head[1] == 23)
		{
			snake_state = 1;
			break;
		}
		sleep(1);
	}
	if (snake_state)
		gameSuccessShow();
	else
		gameOverShow();
	sleep(9);
	clear();
	help();
}

void gameOverShow() {
	printf("=======================================================================\n");
	printf("==============================Game Over================================\n");
	printf("=======================will exit in 3 seconds...=======================\n");
}

void gameSuccessShow() {
	printf("=======================================================================\n");
	printf("============================Congratulation!================================\n");
	printf("=======================will exit in 3 seconds...=======================\n");
}

//listener for key press
PUBLIC void judgeInpt(u32 key)
{
	char output[2] = { '\0', '\0' };

	if (!(key & FLAG_EXT)) {
		output[0] = key & 0xFF;
		if (output[0] == 'a') changeToLeft();
		if (output[0] == 's') changeToDown();
		if (output[0] == 'd') changeToRight();
		if (output[0] == 'w') changeToUp();
		if (output[0] == 'j') Achess();
	}
}


//snake game code
PUBLIC int listenerStart = 0;
PUBLIC char chessMan = 'n';
struct Snake {   //every node of the snake 
	int x, y;
	int now;   //0,1,2,3 means left right up down   
}Snake[8 * 16];  //Snake[0] is the head，and the other nodes are recorded in inverted order，eg: Snake[1] is the tail
				 //change the direction of circle
void changeToLeft() {

	if (snakeControl == 1)
	{
		move_direction = 3;
		if (listenerStart == 1) {
			Snake[0].now = 0;
			listenerStart = 0;
		}
	}
	else
	{
		chessMan = 'a';
	}


}
void changeToDown() {
	if (snakeControl == 1)
	{
		move_direction = 2;
		if (listenerStart == 1) {
			Snake[0].now = 3;
			listenerStart = 0;
		}
	}
	else {
		chessMan = 's';
	}

}
void changeToRight() {
	if (snakeControl == 1)
	{
		move_direction = 4;
		if (listenerStart == 1) {
			Snake[0].now = 1;
			listenerStart = 0;
		}
	}
	else {
		chessMan = 'd';
	}

}
void changeToUp() {
	if (snakeControl == 1)
	{
		move_direction = 1;
		if (listenerStart == 1) {
			Snake[0].now = 2;
			listenerStart = 0;
		}
	}
	else {
		chessMan = 'w';
	}

}
void Achess()
{
	if (snakeControl == 1)
	{
		return;
	}
	else {
		chessMan = 'j';
	}
}
const int mapH = 8;
const int mapW = 16;
char sHead = '@';
char sBody = 'O';
char sFood = '#';
char sNode = '.';
char Map[8][16];
int food[8][2] = { { 4,3 },{ 6, 1 },{ 2, 0 },{ 8, 9 },{ 3, 4 },{ 1,12 },{ 0, 2 },{ 5, 13 } };
int foodNum = 0;
int eat = -1;
int win = 8;
int sLength = 1;
int overOrNot = 0;
int dx[4] = { 0, 0, -1, 1 };
int dy[4] = { -1, 1, 0, 0 };

void gameInit();
void food_init();
void show();
void move();
void checkBorder();
void checkHead(int x, int y);
void action();

void SnakeGame() {
	clear();
	gameInit();
	show();
}
void gameInit()
{
	int i, j;
	int headx = 0;
	int heady = 0;

	memset(Map, '.', sizeof(Map));  //init map with '.'  

	Map[headx][heady] = sHead;
	Snake[0].x = headx;
	Snake[0].y = heady;
	Snake[0].now = -1;

	food_init();   //init target 
	for (i = 0; i < mapH; i++)
	{
		for (j = 0; j < mapW; j++)
			printf("%c", Map[i][j]);
		printf("\n");
	}
	printf("press 'a''s''d''w' key and start the game\n");

	listenerStart = 1;
	while (listenerStart);
}
void food_init() {
	int fx, fy;
	int tick;
	while (1)
	{
		//fx = food[foodNum%8][0];                                                                                                     
		//fy = food[foodNum%8][1];       
		tick = get_ticks();
		fx = tick%mapH;
		fy = tick%mapW;
		if (Map[fx][fy] == '.')
		{
			eat++;
			Map[fx][fy] = sFood;
			break;
		}
		foodNum++;
	}
}
void show() {
	int i, j;
	printf("init done");
	while (1)
	{
		listenerStart = 1;
		if (eat < 4) {
			sleep(3);
		}
		else if (eat < 7) {
			sleep(2);
		}
		else {
			sleep(1);
		}

		//while(listenerStart);

		move();
		if (overOrNot)
		{
			snakeControl = 0;
			printf("===========================================================\n");
			printf("========================Game Over==========================\n");
			printf("=================will exit in 3 seconds...=================\n");
			sleep(9);
			clear();
			help();
			break;
		}
		if (eat == win)
		{
			snakeControl = 0;
			printf("===========================================================\n");
			printf("======================Congratulations======================\n");
			printf("=================will exit in 3 seconds...=================\n");
			sleep(9);
			clear();
			help();
			break;
		}
		clear();
		for (i = 0; i < mapH; i++)
		{
			for (j = 0; j < mapW; j++)
				printf("%c", Map[i][j]);
			printf("\n");
		}

		printf("Have fun!\n");
		printf("You have ate:%d\n", eat);
		/*for(i=0; i < sLength; i++){
		printf("x:%d",Snake[i].x);
		printf("\n");
		printf("y:%d",Snake[i].y);
		printf("\n");
		}*/
	}
}
void move() {
	int i, x, y;
	int t = sLength;
	x = Snake[0].x;
	y = Snake[0].y;
	Snake[0].x = Snake[0].x + dx[Snake[0].now];  //now the Snake[0] is the head in the next step
	Snake[0].y = Snake[0].y + dy[Snake[0].now];

	Map[x][y] = '.';  //when the snake only have head, it's necessary
	checkBorder();
	checkHead(x, y);
	if (sLength == t)  //did not eat
		for (i = 1; i < sLength; i++)  //from the tail  
		{
			if (i == 1)   //tail  
				Map[Snake[i].x][Snake[i].y] = '.';

			if (i == sLength - 1)  //the node after the head 
			{
				Snake[i].x = x;
				Snake[i].y = y;
				Snake[i].now = Snake[0].now;
			}
			else
			{
				Snake[i].x = Snake[i + 1].x;
				Snake[i].y = Snake[i + 1].y;
				Snake[i].now = Snake[i + 1].now;
			}
			Map[Snake[i].x][Snake[i].y] = 'O';
		}
}
void checkBorder() {
	if (Snake[0].x < 0 || Snake[0].x >= mapH || Snake[0].y < 0 || Snake[0].y >= mapW)
		overOrNot = 1;
}
void checkHead(int x, int y) {
	if (Map[Snake[0].x][Snake[0].y] == '.')
		Map[Snake[0].x][Snake[0].y] = '@';
	else if (Map[Snake[0].x][Snake[0].y] == '#')
	{
		Map[Snake[0].x][Snake[0].y] = '@';
		Snake[sLength].x = x;      //new node 
		Snake[sLength].y = y;
		Snake[sLength].now = Snake[0].now;
		Map[Snake[sLength].x][Snake[sLength].y] = 'O';
		sLength++;
		food_init();
	}
	else
	{
		overOrNot = 1;
	}
}
int zzz = 1;
int rand()
{
	if (zzz % 10 == 1)
	{
		zzz++;
		return 145;
	}
	else if (zzz % 10 == 2)
	{
		zzz++;
		return 261;
	}
	else if (zzz % 10 == 3)
	{
		zzz++;
		return 84;
	}
	else if (zzz % 10 == 4)
	{
		zzz++;
		return 125;
	}
	else if (zzz % 10 == 5)
	{
		zzz++;
		return 127;
	}
	else if (zzz % 10 == 6)
	{
		zzz++;
		return 126;
	}
	else if (zzz % 10 == 7)
	{
		zzz++;
		return 54;
	}
	else if (zzz % 10 == 8)
	{
		zzz++;
		return 98;
	}
	else if (zzz % 10 == 9)
	{
		zzz++;
		return 18;
	}
	else if (zzz % 10 == 0)
	{
		zzz++;
		return 19;
	}
}



/*****************************************************************************
*                                untar
*****************************************************************************/
/**
* Extract the tar file and store them.
*
* @param filename The tar file.
*****************************************************************************/
void untar(const char * filename)
{
	//printf("[extract `%s'\n", filename);
	int fd = open(filename, O_RDWR);
	assert(fd != -1);

	char buf[SECTOR_SIZE * 16];
	int chunk = sizeof(buf);
	int i = 0;
	int bytes = 0;

	while (1) {
		bytes = read(fd, buf, SECTOR_SIZE);
		assert(bytes == SECTOR_SIZE); /* size of a TAR file
									  * must be multiple of 512
									  */
		if (buf[0] == 0) {
			if (i == 0)
				//printf("    need not unpack the file.\n");
				break;
		}
		i++;

		struct posix_tar_header * phdr = (struct posix_tar_header *)buf;

		/* calculate the file size */
		char * p = phdr->size;
		int f_len = 0;
		while (*p)
			f_len = (f_len * 8) + (*p++ - '0'); /* octal */

		int bytes_left = f_len;
		int fdout = open(phdr->name, O_CREAT | O_RDWR | O_TRUNC);
		if (fdout == -1) {
			printf("    failed to extract file: %s\n", phdr->name);
			printf(" aborted]\n");
			close(fd);
			return;
		}
		printf("    %s", phdr->name);
		while (bytes_left) {
			int iobytes = min(chunk, bytes_left);
			read(fd, buf,
				((iobytes - 1) / SECTOR_SIZE + 1) * SECTOR_SIZE);
			bytes = write(fdout, buf, iobytes);
			assert(bytes == iobytes);
			bytes_left -= iobytes;
			printf(".");
		}
		printf("\n");
		close(fdout);
	}

	if (i) {
		lseek(fd, 0, SEEK_SET);
		buf[0] = 0;
		bytes = write(fd, buf, 1);
		assert(bytes == 1);
	}

	close(fd);

	//printf(" done, %d files extracted]\n", i);
}

/*****************************************************************************
*                                shabby_shell
*****************************************************************************/
/**
* A very very simple shell.
*
* @param tty_name  TTY file name.
*****************************************************************************/
void shabby_shell(const char * tty_name)
{
	int fd_stdin = open(tty_name, O_RDWR);
	assert(fd_stdin == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	char rdbuf[128];

	while (1) {
		write(1, "$ ", 2);
		int r = read(0, rdbuf, 70);
		rdbuf[r] = 0;

		int argc = 0;
		char * argv[PROC_ORIGIN_STACK];
		char * p = rdbuf;
		char * s;
		int word = 0;
		char ch;
		do {
			ch = *p;
			if (*p != ' ' && *p != 0 && !word) {
				s = p;
				word = 1;
			}
			if ((*p == ' ' || *p == 0) && word) {
				word = 0;
				argv[argc++] = s;
				*p = 0;
			}
			p++;
		} while (ch);
		argv[argc] = 0;

		int fd = open(argv[0], O_RDWR);
		if (fd == -1) {
			if (rdbuf[0]) {
				write(1, "{", 1);
				write(1, rdbuf, r);
				write(1, "}\n", 2);
			}
		}
		else {
			close(fd);
			int pid = fork();
			if (pid != 0) { /* parent */
				int s;
				wait(&s);
			}
			else {	/* child */
				execv(argv[0], argv);
			}
		}
	}

	close(1);
	close(0);
}

/*****************************************************************************
*                                Init
*****************************************************************************/
/**
* The hen.
*
*****************************************************************************/
void Init()
{
	int fd_stdin = open("/dev_tty0", O_RDWR);
	assert(fd_stdin == 0);
	int fd_stdout = open("/dev_tty0", O_RDWR);
	assert(fd_stdout == 1);

	printf("Init() is running ...\n");

	/* extract `cmd.tar' */
	untar("/cmd.tar");


	char * tty_list[] = { "/dev_tty1", "/dev_tty2" };

	int i;
	for (i = 0; i < sizeof(tty_list) / sizeof(tty_list[0]); i++) {
		int pid = fork();
		if (pid != 0) { /* parent process */
			printf("[parent is running, child pid:%d]\n", pid);
		}
		else {	/* child process */
			printf("[child is running, pid:%d]\n", getpid());
			close(fd_stdin);
			close(fd_stdout);

			shabby_shell(tty_list[i]);
			assert(0);
		}
	}

	while (1) {
		int s;
		int child = wait(&s);
		//printf("child (%d) exited with status: %d.\n", child, s);
	}

	assert(0);
}


void clear()
{
	clear_screen(0, console_table[current_console].cursor);
	console_table[current_console].crtc_start = 0;
	console_table[current_console].cursor = 0;

}
void help()
{
	printf("=============================================================================\n");
	printf("Command List     :\n");
	printf("1. process       : A process manage,show you all process-info here\n");
	printf("2. fileSystem    : Run the file manager\n");
	printf("3. clear         : Clear the screen\n");
	printf("4. help          : Show this help message\n");
	printf("5. guessNumber   : Run a simple number guess game\n");
	printf("6. maze          : Run a maze game\n");
	printf("7. information   : Show students' information\n");
	printf("8. snake         : Play a greedy eating Snake\n");
	printf("9. 2048          : Play a 2048 game\n");
	printf("10.box           : Play a push box game\n");
	printf("==============================================================================\n");
}
void ShowOsScreen()
{
	clear();
	printf("*****************************************************\n");
	printf("*      * * *                   * * * *              *\n");
	printf("*    *       *               *         *            *\n");
	printf("*   *         *               *                     *\n");
	printf("*  *           *                *                   *\n");
	printf("*  *           *                   *                *\n");
	printf("*   *         *                      *              *\n");
	printf("*    *       *               *         *            *\n");
	printf("*      * * *                   * * * *              *\n");
	printf("*    WRITEEN BY          1753910  Ma Siteng         *\n");
	printf("*    WRITEEN BY          1753948  Zhang Yao         *\n");
	printf("*    WRITEEN BY          1751984  Wang Gefei        *\n");
	printf("*****************************************************\n");
}
void printProcess()
{
	if (schedule_flag == RR_SCHEDULE)
	{
		for (int i = 6; i < 9; i++)
		{
			if (proc_table[i].p_runable)
			{
				switch (i)
				{
				case 6:
					out_char(tty_table[1].console, 'A');
					break;
				case 7:
					out_char(tty_table[1].console, 'B');
					break;
				case 8:
					out_char(tty_table[1].console, 'C');
					break;

				}
				//delay(20);
			}
		}
	}
	else if (schedule_flag == PRIO_SCHEDULE)
	{
		int greatest_ticks = 0, p_proc_ready = 0;
		while (!greatest_ticks)
		{
			for (int i = 6; i < 9; i++)
			{
				if (proc_table[i].p_runable)
				{
					if (proc_table[i].ticks > greatest_ticks)
					{
						greatest_ticks = proc_table[i].ticks;
						p_proc_ready = i;
					}
				}
			}
			if (!greatest_ticks)
			{
				for (int i = 6; i < 9; i++)
				{
					if (proc_table[i].p_runable)
					{
						proc_table[i].ticks = proc_table[i].priority;
					}
				}
			}
		}
		switch (p_proc_ready)
		{
		case 6:
			out_char(tty_table[1].console, 'A');
			//delay(20);
			proc_table[6].ticks--;
			break;
		case 7:
			out_char(tty_table[1].console, 'B');
			//delay(20);
			proc_table[7].ticks--;
			break;
		case 8:
			out_char(tty_table[1].console, 'C');
			//delay(20);
			proc_table[8].ticks--;
			break;
		default:
			break;
		}
	}

}

void ProcessManage()
{
	clear();
	printf("=================================================\n");
	printf("================================ProcessManage==================================\n");
	printf("          ===== Name =====Priority=====State======Schedule Method=====\n");
	for (int i = 6; i< 9; i++)
	{

		printf("          ===== %s ========%2d=======",
			proc_table[i].name,
			proc_table[i].priority);
		if (proc_table[i].p_runable) {
			printf("running===========");
		}

		else
			printf("suspened==========");
		if (schedule_flag == RR_SCHEDULE) {
			printf("RR===========\n");
		}

		else
			printf("PRIO=========\n");
	}
	printf("===============================================================================\n");
	printf("=                               command tips:                                 =\n");
	printf("=                   YOU SHOULD use 'run' to BEGIN YOUR TEST                   =\n");
	printf("=        AND use 'ALT+F2' to see the result after PAUSE ALL PROCESSES         =\n");
	printf("=                         AND use 'ALT+F1' to RETURN                          =\n");
	printf("=              'pause a/b/c' or 'pause all' -> pause the process              =\n");
	printf("=                'resume a/b/c' or 'run' -> resume the process                =\n");
	printf("=                  'show all process' -> no hidden process                    =\n");
	printf("=                  'up a/b/c' -> higher process priority                      =\n");
	printf("=                 'down a/b/c' -> lower process priority                      =\n");
	printf("=       'RR schedule' or 'PRIO schedule' -> change the schedule method        =\n");

	printf("===============================================================================\n");
}
void ResumeProcess(int num)
{
	/*
	for(int i = 0;i<NR_TASKS + NR_PROCS; i++)
	{
	if(proc_table[i].priority == 0)  //系统程序
	{
	continue;
	}
	else
	{
	if(i == num)				//只有一个进程在运行，其他进程等待,A proc is runnable if p_flags==0
	{
	proc_table[i].p_flags = 0;
	}
	else
	{
	proc_table[i].p_flags = 1;
	}
	}
	}
	*/
	proc_table[num].p_runable = 1;
	ProcessManage();
}
void pauseProcess(int num)
{
	proc_table[num].p_runable = 0;
	ProcessManage();
}
void UpPriority(int num)
{
	//四个特权级：0,1,2,3 数字越小特权级越大

	if (proc_table[num].priority >= 800)
	{
		printf("!!!!you can not up the priority!!!!\n");
	}
	else
	{
		proc_table[num].priority = proc_table[num].priority + 10;
		proc_table[num].ticks = proc_table[num].priority;
	}
	ProcessManage();
}
void DownPriority(int num)
{
	if (proc_table[num].priority <= 5)
	{
		printf("!!!!you can not Down the priority!!!!\n");
	}
	else
	{
		proc_table[num].priority = proc_table[num].priority - 10;
		proc_table[num].ticks = proc_table[num].priority;
	}
	ProcessManage();
}

void FileSystem(int fd_stdin, int fd_stdout)
{
	clear();
	char tty_name[] = "/dev_tty1";
	//int fd_stdin  = open(tty_name, O_RDWR);
	//assert(fd_stdin  == 0);
	//int fd_stdout = open(tty_name, O_RDWR);
	//assert(fd_stdout == 1);
	char rdbuf[128];
	char cmd[8];
	char filename[120];
	char buf[1024];
	int m, n;
	printf("=========================================================\n");
	printf("==============         File Manager         =============\n");
	printf("==============       Kernel on Orange's     =============\n");
	printf("=========================================================\n");
	printf("Command List     :\n");
	printf("1. create [filename]       : Create a new file \n");
	printf("2. read [filename]         : Read the file\n");
	printf("3. write [filename]        : Write at the end of the file\n");
	printf("4. delete [filename]       : Delete the file\n");
	printf("5. rename [filename]       : Rename the file\n");
	printf("6. lseek  [filename]       : reset the point in file\n");
	printf("7. help                    : Display the help message\n");
	printf("8. exit                    : Exit the file system\n");
	printf("!!!!you can not up the priority!!!!\n");
	printf("=========================================================\n");


	int re_flag = 0;
	while (1) {
		printf("$fileManage-> ");
		int r = read(fd_stdin, rdbuf, 70);
		rdbuf[r] = 0;
		if (strcmp(rdbuf, "help") == 0)
		{
			printf("==================================================================\n");
			printf("Command List     :\n");
			printf("1. create [filename]       : Create a new file \n");
			printf("2. read   [filename]       : Read the file\n");
			printf("3. write  [filename]       : Write at the end of the file\n");
			printf("4. delete [filename]       : Delete the file\n");
			printf("5. rename [filename]       : Rename the file\n");
			printf("6. lseek  [filename]       : reset the point in file\n");
			printf("7. help                    : Display the help message\n");
			printf("8. exit                    : Exit the file system\n");
			printf("==================================================================\n");
		}
		else if (strcmp(rdbuf, "exit") == 0)
		{
			clear();
			help();
			break;
		}
		else
		{
			int fd;
			int i = 0;
			int j = 0;
			char temp = -1;
			while (rdbuf[i] != ' ')
			{
				cmd[i] = rdbuf[i];
				i++;
			}
			cmd[i++] = 0;
			while (rdbuf[i] != 0)
			{
				filename[j] = rdbuf[i];
				i++;
				j++;
			}
			filename[j] = 0;

			/*
			if(re_flag == 1)
			{
			m = unlink(filename);
			if (m == 0)
			{
			printf("Rename file '%s' -> '%s' successful!\n",filename,rdbuf);
			}
			else
			{
			printf("Failed to rename the file,please try again!\n");
			}
			re_flag = 0;
			}
			*/
			if (strcmp(cmd, "create") == 0)
			{
				fd = open(filename, O_CREAT | O_RDWR);
				if (fd == -1)
				{
					printf("Failed to create file! Please check the fileaname!\n");
					continue;
				}
				buf[0] = 0;
				write(fd, buf, 1);
				printf("File created: %s (fd %d)\n", filename, fd);
				close(fd);
			}
			else if (strcmp(cmd, "read") == 0)
			{
				fd = open(filename, O_RDWR);
				if (fd == -1)
				{
					printf("Failed to open file! Please check the fileaname!\n");
					continue;
				}
				n = read(fd, buf, 1024);

				printf("%s\n", buf);
				close(fd);
			}
			else if (strcmp(cmd, "write") == 0)
			{
				fd = open(filename, O_RDWR);
				if (fd == -1)
				{
					printf("Failed to open file! Please check the fileaname!\n");
					continue;
				}
				m = read(fd_stdin, rdbuf, 80);
				rdbuf[m] = 0;
				n = write(fd, rdbuf, m + 1);
				close(fd);
			}
			else if (strcmp(cmd, "delete") == 0)
			{
				m = unlink(filename);
				if (m == 0)
				{
					printf("File deleted!\n");
					continue;
				}
				else
				{
					printf("Failed to delete file! Please check the fileaname!\n");
					continue;
				}
			}
			else if (strcmp(cmd, "rename") == 0)
			{
				int n_fd;
				int n1;
				int n2;
				fd = open(filename, O_RDWR);
				if (fd == -1)
				{
					printf("File not exit! Please check the fileaname!\n");
					continue;
				}
				printf("Please input new filename: ");
				m = read(fd_stdin, rdbuf, 80);
				rdbuf[m] = 0;
				printf("new file name:%s\n", rdbuf);
				n_fd = open(rdbuf, O_CREAT | O_RDWR);
				if (n_fd == -1)
				{
					printf("FileName has exit! Please try another fileaname!\n");
					continue;
				}
				n1 = read(fd, buf, 1024);
				printf("buf:%s\n", buf);
				n2 = write(n_fd, buf, n1 + 1);
				close(n_fd);
				close(fd);
				//re_flag = 1;
			}
			else if (strcmp(cmd, "lseek") == 0)
			{
				fd = open(filename, O_RDWR);
				if (fd == -1)
				{
					printf("Failed to open file! Please check the fileaname!\n");
					continue;
				}
				printf("Choose whence value:\n");
				printf("1.SEEK_SET\n");
				printf("2.SEEK_CUR\n");
				printf("3.SEEK_END\n");
				printf("Use the num to choose: ");
				m = read(fd_stdin, rdbuf, 80);
				rdbuf[m] = 0;
				int a = my_atoi(rdbuf);
				printf("aaaaaa%d\n", a);
				printf("Set the offset value: \n");
				m = read(fd_stdin, rdbuf, 80);
				rdbuf[m] = 0;
				int b = my_atoi(rdbuf);
				switch (a)
				{
				case 1:
				{
					n = lseek(fd, b, SEEK_SET);
					n = read(fd, buf, 2);
					printf("%s\n", buf);
					break;
				}
				case 2:
				{
					n = lseek(fd, b, SEEK_CUR);
					n = read(fd, buf, 2);
					printf("%s\n", buf);
					break;
				}
				case 3:
				{
					n = lseek(fd, b, SEEK_END);
					n = read(fd, buf, 2);
					printf("%s\n", buf);
					break;
				}
				}
			}
			else
			{
				printf("Command not found, Please check!\n");
				continue;
			}
		}
	}
	//assert(0); /* never arrive here */
}



/*======================================================================*
TestA
*======================================================================*/
void TestA()
{
	int fs_flag = 0;			//文件管理flag, 1为进入文件管理模块，0为未进入
	int pm_flag = 0;			//进程调度flag，1为进入进程调度模块，0为未进入
	for (int k = 6; k<9; k++)
	{
		proc_table[k].ticks = 0;
	}
	int i = 0;
	/*while (1) {
	printf("<Ticks:%x>", get_ticks());
	milli_delay(200);
	}*/
	int fd;
	int n;
	char tty_name[] = "/dev_tty0";
	char rdbuf[128];
	int fd_stdin = open(tty_name, O_RDWR);
	assert(fd_stdin == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	clear();
	ShowOsScreen();
	while (1)
	{
		while (1) {
			//clear();
			//ShowOsScreen();
			printl("[root@localhost /] ");
			int r = read(fd_stdin, rdbuf, 70);
			rdbuf[r] = 0;
			if (strcmp(rdbuf, "help") == 0)
			{
				help();
			}
			else if (strcmp(rdbuf, "guessNumber") == 0)
			{
				printf("Welcome for the small game -- Guess Number!Guess a number between 0 to 1000 and 'exit' for return!");
				//srand((usigned)time(NULL));
				//int number_to_guess = (rand() % (1000-0+1))+ 0;	//随机生成0到1000的随机数字
				int number_to_guess = 125;
				clear();
				while (1) {
					printl("[Guess a number(0--1000)/] ");
					int r = read(fd_stdin, rdbuf, 70);
					rdbuf[r] = 0;
					if (strcmp(rdbuf, "Exit") == 0)
					{
						printf("All right, turn back!The reslut is %d .\n", number_to_guess);
						break;
					}
					int num = my_atoi(rdbuf);
					if (num > number_to_guess)
					{
						printf("Oops,this number is too biger,why not try again?\n");
						continue;
					}
					else if (num < number_to_guess)
					{
						printf("Oops,this number is samller than it , try more once.\n");
						continue;
					}
					else if (num == number_to_guess)
					{
						printf("Congratulation.....It is this!\n");
						help();
						break;
					}
				}
			}
			else if (strcmp(rdbuf, "clear") == 0)
			{
				ShowOsScreen();
			}
			else if (strcmp(rdbuf, "fileSystem") == 0)
			{
				fs_flag = 1;
				break;
			}
			else if (strcmp(rdbuf, "information") == 0)
			{
				printf("The OS Gorup is: \n");
				printf("1753910 Ma Siteng \n");
				printf("1753948 Zhang Yao \n");
				printf("1751984 Wang Gefei \n");
			}
			else if (strcmp(rdbuf, "process") == 0)
			{
				pm_flag = 1;
				ProcessManage();
			}
			else if (pm_flag == 1)		//已进入进程调度模块
			{
				if (strcmp(rdbuf, "resume a") == 0)
				{
					ResumeProcess(6);
				}
				else if (strcmp(rdbuf, "resume b") == 0)
				{
					ResumeProcess(7);
				}
				else if (strcmp(rdbuf, "run") == 0)
				{
				
					proc_table[6].p_runable = 1;
					proc_table[7].p_runable = 1;
					proc_table[8].p_runable = 1;
					ProcessManage();

				}
				else if (strcmp(rdbuf, "pause all") == 0)
				{
					for (int k = 0; k<100; k++)
					{
						printProcess();
					}
					out_char(tty_table[1].console, '\n');
					out_char(tty_table[1].console, '\n');
					proc_table[6].p_runable = 0;
					proc_table[7].p_runable = 0;
					proc_table[8].p_runable = 0;
					ProcessManage();

				}
				else if (strcmp(rdbuf, "RR schedule") == 0)
				{
					schedule_flag = RR_SCHEDULE;
					ProcessManage();

				}
				else if (strcmp(rdbuf, "PRIO schedule") == 0)
				{
					schedule_flag = PRIO_SCHEDULE;
					ProcessManage();

				}
				else if (strcmp(rdbuf, "resume c") == 0)
				{
					ResumeProcess(8);
				}
				else if (strcmp(rdbuf, "pause a") == 0)
				{
					pauseProcess(6);
				}
				else if (strcmp(rdbuf, "pause b") == 0)
				{
					pauseProcess(7);
				}
				else if (strcmp(rdbuf, "pause c") == 0)
				{
					pauseProcess(8);
				}
				else if (strcmp(rdbuf, "up a") == 0)
				{
					UpPriority(6);
				}
				else if (strcmp(rdbuf, "up b") == 0)
				{
					UpPriority(7);
				}
				else if (strcmp(rdbuf, "up c") == 0)
				{
					UpPriority(8);
				}
				else if (strcmp(rdbuf, "down a") == 0)
				{
					DownPriority(6);
				}
				else if (strcmp(rdbuf, "down b") == 0)
				{
					DownPriority(7);
				}
				else if (strcmp(rdbuf, "down c") == 0)
				{
					DownPriority(8);
				}
				else if (strcmp(rdbuf, "exit") == 0)
				{
					pm_flag = 0;
					clear();
					help();
				}
				else
				{
					printf("not such command for process management!!\n");
					ProcessManage();
				}
			}
			else if (strcmp(rdbuf, "snake") == 0)
			{
				snakeControl = 1;
				SnakeGame();
			}
			else if (strcmp(rdbuf, "maze") == 0) {
				move_direction = 4;
				snake_head[0] = 1;
				snake_head[1] = 2;
				Maze();
			}
			else if (strcmp(rdbuf, "2048") == 0) {
				game2048(fd_stdin);
			}
			else if (strcmp(rdbuf, "box") == 0) {
				Sokoban(fd_stdin);
			}
			else
				printf("Command not found,please check!For more command information please use 'help' command.\n");
		}
		FileSystem(fd_stdin, fd_stdout);
	}
}


/*======================================================================*
TestB
*======================================================================*/
void TestB()
{
	char tty_name[] = "/dev_tty1";

	int fd_stdin = open(tty_name, O_RDWR);
	assert(fd_stdin == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	char rdbuf[128];

	while (1) {
		printf("$ ");
		int r = read(fd_stdin, rdbuf, 70);
		rdbuf[r] = 0;

		if (strcmp(rdbuf, "hello") == 0)
			printf("hello world!\n");
		else
			if (rdbuf[0])
				printf("{%s}\n", rdbuf);
	}

	assert(0); /* never arrive here */
}

/*======================================================================*
TestB
*======================================================================*/
void TestC()
{
	for (;;);
}

/*****************************************************************************
*                                panic
*****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	int i;
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	i = vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}


char getch(int fd_stdin)
{
	//char rdbuf[128];
	//int r = read(fd_stdin, rdbuf, 70);
	//rdbuf[r] = 0;
	//return my_atoi(rdbuf);
	//printf("rdbuf is :%c\n.",rdbuf);
	//printf("ChessMan is :%c\n.",chessMan);
	char s = chessMan;
	chessMan = 'n';
	return s;
}


/*****************************************************************************
*                                2048 game
*****************************************************************************/

int num[4][4];
int score, gameover, ifappear, gamew, gamef, gameb, move_2048;
char key;
void explation(int fd_stdin)
{
	void menu(int fd_stdin);
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*****************************************\n");
	printf("\t\t******************rules***************\n");
	printf("\t\t*****************************************\n");
	printf("\t\t*****************************************\t\t\n");
	printf("PRESS 'up' 'down' 'left' 'right' OR 'W' 'A' 'S' 'D' to move the blocks\n");
	printf("If the map is filled with blocks, you fail\n");
	printf("If there's an 2048, you win\n");
	printf("after 5s to return...\n");
	sleep(15);
	getch(fd_stdin);
	clrscr();
	menu(fd_stdin);
}
void gamefaile(int fd_stdin)
{
	int i, j;
	clrscr();
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t******************you fail***************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t\t---------------------\n\t\t\t");
	for (j = 0; j<4; j++)
	{
		for (i = 0; i<4; i++)
			if (num[j][i] == 0)
				printf("|    ");
			else
				printf("|%4d", num[j][i]);
		printf("|\n");
		printf("\t\t\t---------------------\n\t\t\t");
	}
	printf("YOUR SCORE:%d, MOVES:%d\n", score, move_2048);
	printf("PRESS any key to return...\n");
	sleep(15);
	getch(fd_stdin);

	clear();
	help();

}
void gamewin(int fd_stdin)
{
	int i, j;
	clrscr();
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*******************you win***************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t\t---------------------------------------\t\t\n\t\t\t");
	for (j = 0; j<4; j++)
	{
		for (i = 0; i<4; i++)
			if (num[j][i] == 0)
				printf("|    ");
			else
				printf("|%4d", num[j][i]);
		printf("|\n");
		printf("\t\t\t---------------------\n\t\t\t");
	}
	printf("YOUR SCORE:%d, MOVES:%d\n", score, move_2048);
	printf("PRESS any key to return...\n");
	sleep(15);
	getch(fd_stdin);
	clrscr();
	help();
}
void prin()
{
	int i, j;
	clrscr();
	printf("\t\t*****************************************\t\t\n");//输出界面
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t******************START GAME*************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("\t\t*PRESS 'W' 'A' 'S' 'D' to move the block*\t\t\n");//输出操作提示语句
	printf("\t\t***********PRESS 'j' to return***********\t\t\n");
	printf("\t\t-----------------------------------------\t\t\n\t\t\t");
	for (j = 0; j<4; j++)                 //输出4*4的表格
	{
		for (i = 0; i<4; i++)
			if (num[j][i] == 0)
				printf("|    ");
			else
				printf("|%4d", num[j][i]);
		printf("|\n");
		printf("\t\t\t---------------------\n\t\t\t");
	}
	printf("YOUR SCORE: %d, MOVES:%d\n", score, move_2048);
	//sleep(4);
}
void appear()
{
	int i, j, ran, t[16], x = 0, a, b;
	//srand((int)time(0));          //随机种子初始化
	for (j = 0; j < 4; j++)      //将空白的区域的坐标保存到中间数组t中
		for (i = 0; i < 4; i++)
			if (num[j][i] == 0)
			{
				t[x] = j * 10 + i;
				x++;
			}
	if (x == 1)            //在t中随机取一个坐标
		ran = x - 1;
	else if (x == 0)
		return;
	else
		ran = rand() % (x - 1);
	a = t[ran] / 10;      //取出这个数值的十位数
	b = t[ran] % 10;     //取出这个数值的个位数
						 //srand((int)time(0));
	if ((rand() % 9)>2)    //在此空白区域随机赋值2或4
		num[a][b] = 2;
	else
		num[a][b] = 4;
}
void add(int *p)
{

	int i = 0, b;
	while (i<3)
	{
		if (*(p + i) != 0)
		{
			for (b = i + 1; b < 4; b++)
			{
				if (*(p + b) != 0)
					if (*(p + i) == *(p + b))
					{
						score = score + (*(p + i)) + (*(p + b));
						*(p + i) = *(p + i) + *(p + b);
						if (*(p + i) == 2048)
							gamew = 1;
						*(p + b) = 0;
						i = b + i;
						++ifappear;
						break;
					}
					else
					{
						i = b;
						break;
					}
			}
			if (b == 4)
				i++;
		}
		else
			i++;
	}

}
void Gameplay(int fd_stdin)
{
	char rdbuf[128];
	int i, j, g, e, a, b[4];
	appear();
	appear();
	while (1)
	{
		key = getch(fd_stdin);
		if (key != 'n')
		{
			if (ifappear != 0)
				appear();
			clrscr();
			prin();
			switch (key)
			{
			case 'w':
			case 'W':
			case 72:
				ifappear = 0;
				for (j = 0; j < 4; j++)
				{
					for (i = 0; i < 4; i++)
					{
						b[i] = num[i][j];
						num[i][j] = 0;
					}
					add(b);
					e = 0;
					for (g = 0; g < 4; g++)
					{
						if (b[g] != 0)
						{
							num[e][j] = b[g];
							if (g != e)
								++ifappear;
							e++;
						}
					}
				}
				if (ifappear != 0)
					++move_2048;
				break;
			case 's':
			case 'S':
			case 80:
				ifappear = 0;
				for (j = 0; j < 4; j++)
				{
					for (i = 0; i < 4; i++)
					{
						int k = 3 - i;
						b[i] = num[k][j];
						num[k][j] = 0;
					}
					add(b);
					e = 3;
					for (g = 0; g < 4; g++)
					{
						if (b[g] != 0)
						{
							num[e][j] = b[g];
							if (g != e)
								++ifappear;
							e--;
						}
					}
				}
				if (ifappear != 0)
					++move_2048;
				break;
			case 'a':
			case 'A':
			case  75:
				ifappear = 0;
				for (j = 0; j < 4; j++)
				{
					for (i = 0; i < 4; i++)
					{
						b[i] = num[j][i];
						num[j][i] = 0;
					}
					add(b);
					e = 0;
					for (g = 0; g < 4; g++)
					{
						if (b[g] != 0)
						{
							num[j][e] = b[g];
							if (g != e)
								++ifappear;
							e++;
						}
					}
				}
				if (ifappear != 0)
					++move_2048;
				break;
			case 'd':
			case 'D':
			case  77:
				ifappear = 0;
				for (j = 0; j < 4; j++)
				{
					for (i = 0; i < 4; i++)
					{
						int k = 3 - i;
						b[i] = num[j][k];
						num[j][k] = 0;
					}
					add(b);
					e = 3;
					for (g = 0; g < 4; g++)
					{
						if (b[g] != 0)
						{
							num[j][e] = b[g];
							if (g != e)
								++ifappear;
							e--;
						}
					}
				}
				if (ifappear != 0)
					++move_2048;
				break;
			case 'j':
				clrscr();
				gameb = 1;
				break;

			}
			if (gameb == 1)
				break;
			for (j = 0; j < 4; j++)
			{
				for (i = 0; i < 4; i++)
				{
					if (j < 3)
					{
						if (i < 3)
						{
							if (num[j][i] == num[j + 1][i] || num[j][i] == num[j][i + 1] || num[j][i] == 0)
							{
								gamef = 0;
								break;
							}
							else
								gamef = 1;
						}
						else
						{
							if (num[j][i] == num[j + 1][i] || num[j][i] == 0)
							{
								gamef = 0;
								break;
							}
							else
								gamef = 1;
						}
					}
					else
					{
						if (i < 3)
						{
							if (num[j][i] == num[j][i + 1] || num[j][i] == 0 || num[j][i + 1] == 0)
							{
								gamef = 0;
								break;
							}
							else
								gamef = 1;
						}
					}

				}
				if (gamef == 0)
					break;
			}
			if (gamef == 1 || gamew == 1)
				break;

		}

	}
	if (gamef == 1 || gameb == 1)
		gamefaile(fd_stdin);
	else
		gamewin(fd_stdin);
}
void menu(int fd_stdin)
{
	int n;
	char rdbuf[128];
	clrscr();
	printf("\t\t*****************************************\t\t\n");            //输出游戏菜单的图形
	printf("\t\t*              1 START GAME             *\t\t\n");
	printf("\t\t*              2 RULES                  *\t\t\n");
	printf("\t\t*              3 EXIT GAME              *\t\t\n");
	printf("\t\t*****************************************\t\t\n");
	printf("ENTER 1 OR 2 OR 3:");
	int r = read(fd_stdin, rdbuf, 70);
	rdbuf[r] = 0;
	//int com=getch(fd_stdin);
	//printf("%d",&com);
	/*switch(com)
	{
	case '1':
	Gameplay(fd_stdin);
	break;
	case '2':
	explation(fd_stdin);
	break;
	case '3':
	close_2048();
	break;
	default:
	break;
	}*/
	if (strcmp(rdbuf, "1") == 0)
	{
		Gameplay(fd_stdin);
	}
	else if (strcmp(rdbuf, "2") == 0)
	{
		explation(fd_stdin);
	}
	else if (strcmp(rdbuf, "3") == 0)
	{
		sleep(2);
		clear();
		help();
		return;
	}

}

void game2048(int fd_stdin)
{
	int j, i;
	for (j = 0; j < 4; j++)             //对4*4进行初始赋值为0
		for (i = 0; i < 4; i++)
			num[j][i] = 0;
	gamew = 0;                        //游戏获胜的判断变量初始化
	gamef = 0;                       //游戏失败的判断变量初始化
	gameb = 0;                       //游戏退出的判断变量初始化
	ifappear = 0;                   //判断是否应该随机出现2或4的变量初始化
	score = 0;                     //游戏得分变量初始化
	gameover = 0;                 //游戏是否结束的变量初始化
	move_2048 = 0;                    //游戏的移动步数初始化
	menu(fd_stdin);                     //调用主菜单函数

}



/*****************************************************************************
*                             SokobanGame
*****************************************************************************/

PUBLIC SokobanGame = 0;

int box_map[8][8] = {
	{ 1,1,1,1,1,1,1,1 },
	{ 1,0,0,0,1,0,0,1 },
	{ 1,0,1,0,1,3,4,1 },
	{ 1,0,0,0,0,3,4,1 },
	{ 1,0,1,0,1,3,4,1 },
	{ 1,0,0,0,1,0,0,1 },
	{ 1,1,1,1,1,2,0,1 },
	{ 0,0,0,0,1,1,1,1 }
};

void Sokoban(int fd_stdin)
{
	while (!check() && !SokobanGame) {
		clrscr();
		draw_box_map();
		sleep(3);
		box_move(fd_stdin);
	}
}

void draw_box_map()
{
	int i, j;
	printf("\t\t*******************************************************\t\t\n");   //输出操作提示语句
	printf("\t\t*********PRESS 'W' 'A' 'S' 'D' to move the man*********\t\t\n");
	printf("\t\t***************PRESS 'J' to return*********************\t\t\n");
	printf("\t\t******* #=wall   i=man   O=box   X=box terminal *******\t\t\n");
	printf("\t\t*I=man on the box terminal   !=box on the box terminal*\t\t\n");
	printf("\t\t*******************************************************\t\t\n");

	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++) {
			switch (box_map[i][j]) {
			case 0:
				printf(" ");
				break;
			case 1:
				printf("#"); //wall
				break;
			case 2:
				printf("i"); //man
				break;
			case 3:
				printf("O"); //box
				break;
			case 4:
				printf("X"); //box terminal
				break;
			case 6:
				printf("I"); //man standing on the box terminal
				break;
			case 7:
				printf("!");//box standing on the box terminal
				break;
			}
		}
		printf("\n");
	}
}

void box_move(int fd_stdin)
{
	int  x, y;
	char op = getch(fd_stdin);
	for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 8; j++) {
			if (box_map[i][j] == 2 || box_map[i][j] == 6) {
				x = i;
				y = j;
			}
		}
	}
	switch (op)
	{
	case 'w':
	case 'W':
	case 72:
		if (box_map[x - 1][y] == 0 || box_map[x - 1][y] == 4)
		{
			box_map[x][y] -= 2;
			box_map[x - 1][y] += 2;
		}
		else if (box_map[x - 1][y] == 3 || box_map[x - 1][y] == 7)
		{
			if (box_map[x - 2][y] == 0 || box_map[x - 2][y] == 4)
			{
				box_map[x][y] -= 2;
				box_map[x - 1][y] -= 1;
				box_map[x - 2][y] += 3;
			}
		}
		break;
	case 's':
	case 'S':
	case 80:
		if (box_map[x + 1][y] == 0 || box_map[x + 1][y] == 4)
		{
			box_map[x][y] -= 2;
			box_map[x + 1][y] += 2;
		}
		else if (box_map[x + 1][y] == 3 || box_map[x + 1][y] == 7)
		{
			if (box_map[x + 2][y] == 0 || box_map[x + 2][y] == 4)
			{
				box_map[x][y] -= 2;
				box_map[x + 1][y] -= 1;
				box_map[x + 2][y] += 3;
			}
		}
		break;
	case 'a':
	case 'A':
	case  75:
		if (box_map[x][y - 1] == 0 || box_map[x][y - 1] == 4)
		{
			box_map[x][y] -= 2;
			box_map[x][y - 1] += 2;
		}
		else if (box_map[x][y - 1] == 3 || box_map[x][y - 1] == 7)
		{
			if (box_map[x][y - 2] == 0 || box_map[x][y - 2] == 4)
			{
				box_map[x][y] -= 2;
				box_map[x][y - 1] -= 1;
				box_map[x][y - 2] += 3;
			}
		}
		break;
	case 'd':
	case 'D':
	case  77:
		if (box_map[x][y + 1] == 0 || box_map[x][y + 1] == 4)
		{
			box_map[x][y] -= 2;
			box_map[x][y + 1] += 2;
		}
		else if (box_map[x][y + 1] == 3 || box_map[x][y + 1] == 7)
		{
			if (box_map[x][y + 2] == 0 || box_map[x][y + 2] == 4)
			{
				box_map[x][y] -= 2;
				box_map[x][y + 1] -= 1;
				box_map[x][y + 2] += 3;
			}
		}
		break;
	case 'j':
		clrscr();
		SokobanGame = 1;
		help();
		break;


		/* case e:
		box_map[8][8] = {
		{ 1,1,1,1,1,1,1,1 },
		{ 1,0,0,0,1,0,0,1 },
		{ 1,0,1,0,1,3,4,1 },
		{ 1,0,0,0,0,3,4,1 },
		{ 1,0,1,0,1,3,4,1 },
		{ 1,0,0,0,1,0,0,1 },
		{ 1,1,1,1,1,2,0,1 },
		{ 0,0,0,0,1,1,1,1 }
		};
		SokobanGame = 0;
		clrscr();
		break;*/
	}
}

int check()
{
	int k = 0;
	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			if (box_map[i][j] == 3)
				k++;
		}
	}
	if (k == 0) {
		printf("===========================================================\n");
		printf("======================Congratulations======================\n");
		return 1;
	}
	else {
		return 0;
	}
}














