/* Copyright 2011 Cumulus Networks Inc.  All rights reserved.
/* See License file for licenese. */

/*
 *
 * "simple" hash table implementation useful for O(1) searching based on a key
 * of continuous bytes compared by exact match.
 *
 * This hash table implementation is bare bones, we provide the structure for
 * doing the add, find, delete, and iterate; the user is responsible for
 * maintaining and cleaning up the associated data.
 *
 * For the purposes of freeing user maintained memory, delete provides the data
 * pointer.  Both foreach and free provide callbacks which are run if not set to
 * NULL.  These callback are passed the data pointer (which can be freed).  The
 * foreach passes along a cbargs pointer for stateful traversal of the list.
 *
 * Expected usecase is where the hash table holds a self contained structure
 *
 * typedef struct {
 *     hal_ipv4_addr_t dest_addr;
 *     uint8_t dest_prefix;
 *     int num_next_hops;
 * } hal_route_t;
 *
 * where the keys (dest_addr/dest_prefix in this case) are contained in
 * the same structure as the data.
 */

#ifndef _HASH_TABLE_H_
#define _HASH_TABLE_H_


/* DATA STRUCTURES -----------------------------------------------------------*/

/* copy of the key, pointer to the associated data, and the threading pointer */
typedef struct hash_node_s {
    void *key;
    int key_size;
    void *data;
    struct hash_node_s *next;
} hash_node_t;

/* keeps track of the hash table nodes and size */
typedef struct {
    int size;   // number of buckets
    int count;
    hash_node_t **nodes;
} hash_table_t;


/* METHODS -------------------------------------------------------------------*/

/* allocate hash table memory and bound the size */
hash_table_t *hash_table_alloc(int size);

/* takes hash_table out of existence */
void hash_table_free(hash_table_t *ht, void (*free_cb)(void* data));

/* add key and a pointer to data, return FALSE if the key already exists. */
bool hash_table_add(hash_table_t *ht, void *key, int key_size, void *data);

/* find pointer to data, returns FALSE if key not found */
bool hash_table_find(hash_table_t *ht, void *key, int key_size, void **data);

/* delete entry and provide data pointer for cleanup,  returns FALSE if key not found */
bool hash_table_delete(hash_table_t *ht, void *key, int key_size, void **data);

/* return number of items stored in hash table */
int hash_table_count(hash_table_t *ht);

/* iterate over the table and execute callback */
void hash_table_foreach( hash_table_t *ht,
			 int (*foreach_cb)(void *data, void *cbarg), void *cbarg);

/* foreach callback return values and side effects*/
enum hash_table_foreach_rv {
    hash_table_foreach_done = 0, /* callback was successful, continue */
    hash_table_foreach_delete,   /* delete the hash node, continue */
    last
};


#endif
